using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using NetworkMonitor.Objects;
using System.Runtime.CompilerServices;

namespace NetworkMonitor.LLM.Services
{
    public class AudioGenerator : IAudioGenerator
    {
        private readonly ILogger _logger;
        private readonly Uri[] _workers;                          // e.g. https://space-a.hf.space, ...
        private readonly ConcurrentDictionary<Uri, Circuit> _circuits = new();
        private static readonly HttpClient _http = new HttpClient()
        {
            Timeout = TimeSpan.FromSeconds(60)
        };

        private const int MaxFailuresBeforeOpen = 3;
        private static readonly TimeSpan CircuitOpenFor = TimeSpan.FromSeconds(30);
        private volatile bool _warmed;
        private readonly object _warmLock = new();



        public AudioGenerator(ILogger<OpenAIRunner> logger, SystemParams systemParams)
        {
            _logger = logger;

            // Build _workers from either the list or the legacy single URL
            IEnumerable<string> candidates =
                (systemParams.AudioServiceUrls != null && systemParams.AudioServiceUrls.Count > 0)
                    ? systemParams.AudioServiceUrls                               // IEnumerable<string>
                    : (!string.IsNullOrWhiteSpace(systemParams.AudioServiceUrl)
                        ? new[] { systemParams.AudioServiceUrl }                  // IEnumerable<string>
                        : Enumerable.Empty<string>());

            var workerList = new List<Uri>();
            foreach (var s in candidates)
            {
                if (string.IsNullOrWhiteSpace(s)) continue;
                var trimmed = s.Trim();

                // Avoid the Uri(string, bool) overload by using TryCreate
                if (Uri.TryCreate(trimmed, UriKind.Absolute, out var u) &&
                    (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
                {
                    workerList.Add(u);
                }
            }

            _workers = workerList
                .Distinct() // de-dupe if both list & single had same URL
                .ToArray();

            if (_workers.Length == 0)
                throw new InvalidOperationException("No AudioServiceUrls configured.");
            _logger.LogInformation("TTS workers: {Workers}", string.Join(", ", _workers.Select(u => u.ToString())));

        }

        // ----- Public API -----

        public async Task<string> AudioForResponse(string text)
        {
            try
            {
                var (worker, filename) = await GenerateOnBestWorker(text);
                if (!string.IsNullOrEmpty(filename))
                {
                    var url = BuildFileUrl(worker, filename);
                    _logger.LogInformation($"Audio generated: {url}");
                    return url;
                }
                _logger.LogError("Audio generation failed for single response.");
                return string.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating audio.");
                return string.Empty;
            }
        }

        public List<string> GetChunksFromText(string text, int maxLength = 500)
        {
            var chunks = text.Split(new[] { "\n\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                             .Select(c => c.Trim())
                             .Where(c => !string.IsNullOrWhiteSpace(c))
                             .SelectMany(c => SplitByWordLimit(c, maxLength))
                             .ToList();
            return chunks;
        }

        public async Task<List<string>> AudioForResponseChunks(string text)
        {
            var chunks = GetChunksFromText(text, 500);
            if (chunks.Count == 0) return new List<string>();

            int par = ParallelismFor(chunks.Count);
            using var gate = new SemaphoreSlim(par);

            var tasks = chunks.Select(async (chunk, i) =>
            {
                await gate.WaitAsync();
                try
                {
                    var (worker, filename) = await GenerateOnBestWorker(chunk);
                    var url = string.IsNullOrEmpty(filename) ? "" : BuildFileUrl(worker, filename);
                    return (index: i, url);
                }
                finally
                {
                    gate.Release();
                }
            }).ToArray();

            var results = await Task.WhenAll(tasks);
            return results
                .OrderBy(r => r.index)
                .Select(r => r.url)
                .Where(u => !string.IsNullOrEmpty(u))
                .ToList();
        }

        public async Task<List<string>> AudioForResponseChunksOrderedFastFirst(string text)
        {
            var chunks = GetChunksFromText(text, 500);
            if (chunks.Count == 0) return new List<string>();

            var urls = new string[chunks.Count];

            // 1) First chunk sync (fast first byte)
            var (w0, f0) = await GenerateOnBestWorker(chunks[0]);
            urls[0] = string.IsNullOrEmpty(f0) ? "" : BuildFileUrl(w0, f0);

            // 2) Prefetch the rest, bounded to number of workers
            int par = ParallelismFor(chunks.Count - 1);
            using var gate = new SemaphoreSlim(par);
            var tasks = new Task[chunks.Count - 1];   // <-- keep this one

            for (int i = 1; i < chunks.Count; i++)
            {
                int idx = i;
                tasks[i - 1] = Task.Run(async () =>
                {
                    await gate.WaitAsync();
                    try
                    {
                        var (w, f) = await GenerateOnBestWorker(chunks[idx]);
                        urls[idx] = string.IsNullOrEmpty(f) ? "" : BuildFileUrl(w, f);
                    }
                    finally
                    {
                        gate.Release();
                    }
                });
            }

            // 3) Await in order (preserve sequence)
            for (int i = 0; i < tasks.Length; i++)
                await tasks[i];

            return urls.Where(u => !string.IsNullOrEmpty(u)).ToList();
        }

        public async IAsyncEnumerable<string> StreamAudioInOrder(
         string text,
         [EnumeratorCancellation] CancellationToken ct = default)
        {
            await WarmAsync(ct);
            var chunks = GetChunksFromText(text, 500);
            int N = chunks.Count;
            if (N == 0) yield break;

            int W = Math.Max(1, Math.Min(_workers.Length, N));

            int nextToEmit = 0;
            var buf = new Dictionary<int, string>(capacity: W * 2);

            // per-lane bookkeeping: last index we've launched on this lane
            var lastLaunched = new int[W];

            async Task<(int idx, string url)> Launch(int idx)
            {
                if (idx >= N) return (idx, "");

                var preferred = _workers[idx % W];
                var hedgeDelayMs = 4000;

                using var t1Cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                using var t2Cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

                var t1 = GenerateOnPreferredThenOthers(chunks[idx], preferred, t1Cts.Token);
                var delay = Task.Delay(hedgeDelayMs, ct);

                if (await Task.WhenAny(t1, delay) == t1)
                {
                    var (w, f) = await t1;
                    return (idx, string.IsNullOrEmpty(f) ? "" : BuildFileUrl(w, f));
                }

                var start = Array.IndexOf(_workers, preferred);
                var alt = _workers[(start + 1) % _workers.Length];
                var t2 = GenerateOnPreferredThenOthers(chunks[idx], alt, t2Cts.Token);

                var winner = await Task.WhenAny(t1, t2);
                if (winner == t1) t2Cts.Cancel(); else t1Cts.Cancel();

                var (ww, ff) = await winner;
                return (idx, string.IsNullOrEmpty(ff) ? "" : BuildFileUrl(ww, ff));
            }

            var running = new List<Task<(int idx, string url)>>(W);

            // kick off 0..W-1
            for (int lane = 0; lane < W; lane++)
            {
                running.Add(Launch(lane));
                lastLaunched[lane] = lane;
            }

            // local helper to schedule next for lane if needed
            void ScheduleNextForLane(int idx)
            {
                int lane = idx % W;
                if (lastLaunched[lane] == idx) // we’ve launched exactly up to this idx
                {
                    int next = idx + W;
                    if (next < N)
                    {
                        running.Add(Launch(next));
                        lastLaunched[lane] = next;
                    }
                }
            }

            while (nextToEmit < N)
            {
                var done = await Task.WhenAny(running);
                running.Remove(done);

                var (idx, url) = await done;
                buf[idx] = url ?? "";

                // schedule successor for the lane of the completed task immediately
                ScheduleNextForLane(idx);

                // now drain in order; for each emitted idx, also schedule its lane successor
                while (buf.TryGetValue(nextToEmit, out var readyUrl))
                {
                    buf.Remove(nextToEmit);

                    // schedule before yielding to avoid underutilization during suspension
                    ScheduleNextForLane(nextToEmit);

                    if (!string.IsNullOrEmpty(readyUrl))
                        yield return readyUrl;

                    nextToEmit++;
                }
            }
        }

        private async Task<(Uri worker, string filename)> GenerateOnPreferredThenOthers(
          string text, Uri preferred, CancellationToken ct)
        {
            int start = Array.IndexOf(_workers, preferred);
            if (start < 0) start = 0;

            // Try healthy first, circular order
            for (int step = 0; step < _workers.Length; step++)
            {
                var w = _workers[(start + step) % _workers.Length];
                if (IsCircuitOpen(w)) continue;

                var f = await PostGenerate(w, text, ct);
                if (!string.IsNullOrEmpty(f)) { RecordSuccess(w); return (w, f); }
                RecordFailure(w);
            }

            // Last resort: ignore circuit, circular order
            for (int step = 0; step < _workers.Length; step++)
            {
                var w = _workers[(start + step) % _workers.Length];
                var f = await PostGenerate(w, text, ct);
                if (!string.IsNullOrEmpty(f)) { RecordSuccess(w); return (w, f); }
                RecordFailure(w);
            }

            return (preferred, "");
        }

        private int ParallelismFor(int workItems)
                => Math.Max(1, Math.Min(_workers.Length, workItems));

        private async Task WarmAsync(CancellationToken ct)
        {
            if (_warmed) return;
            lock (_warmLock)
            {
                if (_warmed) return;
                _warmed = true;
            }
            try
            {
                var tiny = "ok";
                var tasks = _workers.Select(w => PostGenerate(w, tiny, ct)).ToArray();
                await Task.WhenAll(tasks);
            }
            catch { /* best-effort */ }
        }
        // ----- Core routing & calls -----

        private async Task<(Uri worker, string filename)> GenerateOnBestWorker(string text)
        {
            if (_workers.Length == 1)
            {
                var w = _workers[0];
                var f = await PostGenerate(w, text);
                return (w, f);
            }

            // Consistent hash to stick sentences to a worker (helps cache locality)
            var preferred = PickWorkerConsistent(text);

            // Try preferred first; on failure, walk others (health-aware)
            var ordered = OrderByHealth(preferred);

            foreach (var w in ordered)
            {
                if (IsCircuitOpen(w)) continue;

                var filename = await PostGenerate(w, text);
                if (!string.IsNullOrEmpty(filename))
                {
                    RecordSuccess(w);
                    return (w, filename);
                }

                RecordFailure(w);
            }

            // Last resort: try everyone even if circuit-open
            foreach (var w in _workers)
            {
                var filename = await PostGenerate(w, text);
                if (!string.IsNullOrEmpty(filename))
                {
                    RecordSuccess(w);
                    return (w, filename);
                }
                RecordFailure(w);
            }

            return (preferred, "");
        }
        // Back-compat overload for call sites that don't pass a CancellationToken
        private Task<string> PostGenerate(Uri worker, string text)
            => PostGenerate(worker, text, CancellationToken.None);

        private async Task<string> PostGenerate(Uri worker, string text, CancellationToken ct)
        {
            try
            {
                var endpoint = new Uri(worker, "/generate_audio");
                var payload = JsonSerializer.Serialize(new { text });
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var req = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };

                // ResponseHeadersRead makes cancellation snappier
                using var res = await _http.SendAsync(
                    req,
                    HttpCompletionOption.ResponseHeadersRead,
                    ct
                );

                var body = await res.Content.ReadAsStringAsync(ct);

                if (!res.IsSuccessStatusCode)
                {
                    _logger.LogWarning("TTS {Worker} failed: {Status} {Body}", worker, (int)res.StatusCode, body);
                    return "";
                }

                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("filename", out var fnEl))
                {
                    var fn = fnEl.GetString() ?? "";
                    _logger.LogInformation("TTS success on {Worker}: {Filename}", worker, fn);
                    return fn;
                }

                _logger.LogWarning("TTS {Worker} returned success without filename: {Body}", worker, body);
                return "";
            }
            catch (TaskCanceledException)
            {
                // fine: this is how we cancel the loser of a hedge
                return "";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TTS error for {Worker}", worker);
                return "";
            }
        }

        private string BuildFileUrl(Uri worker, string filename)
            => new Uri(worker, "/files/" + filename).ToString();

        // ----- Consistent hashing & health -----

        private Uri PickWorkerConsistent(string key)
        {
            // SHA256(key) -> uint64 -> index
            Span<byte> hash = stackalloc byte[32];
            SHA256.HashData(Encoding.UTF8.GetBytes(key), hash);
            ulong v = BitConverter.ToUInt64(hash.Slice(0, 8));
            var idx = (int)(v % (ulong)_workers.Length);
            return _workers[idx];
        }

        private IEnumerable<Uri> OrderByHealth(Uri first)
        {
            // Preferred first, then others by least failures and not circuit-open
            return new[] { first }
                .Concat(_workers.Where(w => w != first))
                .OrderBy(w =>
                {
                    var c = _circuits.GetOrAdd(w, _ => new Circuit());
                    return (IsCircuitOpen(w) ? 1 : 0, c.Failures);
                });
        }

        private bool IsCircuitOpen(Uri w)
        {
            var c = _circuits.GetOrAdd(w, _ => new Circuit());
            return c.OpenUntil.HasValue && c.OpenUntil.Value > DateTimeOffset.UtcNow;
        }

        private void RecordFailure(Uri w)
        {
            var c = _circuits.AddOrUpdate(
                w,
                _ => new Circuit { Failures = 1 },
                (_, old) =>
                {
                    var f = old.Failures + 1;
                    if (f >= MaxFailuresBeforeOpen)
                        return new Circuit { Failures = f, OpenUntil = DateTimeOffset.UtcNow + CircuitOpenFor };
                    return new Circuit { Failures = f, OpenUntil = old.OpenUntil };
                });
            _logger.LogDebug("Circuit {Worker}: failures={Failures}, openUntil={OpenUntil}", w, c.Failures, c.OpenUntil);
        }

        private void RecordSuccess(Uri w)
        {
            _circuits[w] = new Circuit(); // reset
        }

        private sealed class Circuit
        {
            public int Failures { get; init; }
            public DateTimeOffset? OpenUntil { get; init; }
        }

        // ----- Utilities -----

        private static IEnumerable<string> SplitByWordLimit(string text, int maxLength)
        {
            var words = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var buf = new List<string>();
            var len = 0;
            foreach (var w in words)
            {
                var next = (buf.Count == 0 ? 0 : 1) + w.Length;
                if (len + next > maxLength)
                {
                    if (buf.Count > 0) { yield return string.Join(" ", buf); buf.Clear(); len = 0; }
                }
                if (w.Length > maxLength)
                {
                    // in case of a crazy-long token, hard cut
                    yield return w;
                    continue;
                }
                buf.Add(w);
                len += next;
            }
            if (buf.Count > 0) yield return string.Join(" ", buf);
        }
    }
}

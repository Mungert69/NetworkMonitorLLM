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
            var tasks = new Task[chunks.Count - 1];

            for (int i = 1; i < chunks.Count; i++)
            {
                await gate.WaitAsync();
                int idx = i;
                tasks[i - 1] = Task.Run(async () =>
                {
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
            for (int i = 1; i < chunks.Count; i++)
                await tasks[i - 1];

            return urls.Where(u => !string.IsNullOrEmpty(u)).ToList();
        }
        private int ParallelismFor(int workItems)
                => Math.Max(1, Math.Min(_workers.Length, workItems));

        public async IAsyncEnumerable<string> StreamAudioInOrder(
      string text,
      [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            var chunks = GetChunksFromText(text, 500);
            if (chunks.Count == 0) yield break;

            // 1) First chunk sync for instant playback
            var (w0, f0) = await GenerateOnBestWorker(chunks[0]);
            var url0 = string.IsNullOrEmpty(f0) ? "" : BuildFileUrl(w0, f0);
            if (!string.IsNullOrEmpty(url0))
                yield return url0;

            // 2) Schedule the rest concurrently (bounded to workers), but emit in order
            var tasks = new Task<string>[chunks.Count];
            tasks[0] = Task.FromResult(url0);

            int par = ParallelismFor(chunks.Count - 1);
            using var gate = new SemaphoreSlim(par);

            for (int i = 1; i < chunks.Count; i++)
            {
                await gate.WaitAsync(ct);
                int idx = i;
                tasks[idx] = Task.Run(async () =>
                {
                    try
                    {
                        var (w, f) = await GenerateOnBestWorker(chunks[idx]);
                        return string.IsNullOrEmpty(f) ? "" : BuildFileUrl(w, f);
                    }
                    catch
                    {
                        return "";
                    }
                    finally
                    {
                        gate.Release();
                    }
                }, ct);
            }

            // 3) Yield strictly in index order
            for (int i = 1; i < chunks.Count; i++)
            {
                var url = await tasks[i];
                if (!string.IsNullOrEmpty(url))
                    yield return url;
            }
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

        private async Task<string> PostGenerate(Uri worker, string text)
        {
            try
            {
                var endpoint = new Uri(worker, "/generate_audio");
                var payload = JsonSerializer.Serialize(new { text }); // NO output_dir
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");

                using var res = await _http.PostAsync(endpoint, content);
                var body = await res.Content.ReadAsStringAsync();

                if (!res.IsSuccessStatusCode)
                {
                    _logger.LogWarning("TTS {Worker} failed: {Status} {Body}", worker, (int)res.StatusCode, body);
                    return "";
                }

                var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("filename", out var fnEl))
                {
                    return fnEl.GetString() ?? "";
                }

                _logger.LogWarning("TTS {Worker} returned success without filename payload: {Body}", worker, body);
                return "";
            }
            catch (TaskCanceledException tce)
            {
                _logger.LogWarning(tce, "TTS timeout for {Worker}", worker);
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

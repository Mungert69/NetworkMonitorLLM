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
using System.Diagnostics;

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

        // ---- Latency-aware hedging support (uses your WorkerMetrics/HedgePolicy/FileWorkerMetricsStore) ----
        private readonly ConcurrentDictionary<Uri, WorkerMetrics> _metrics = new();
        private readonly ConcurrentDictionary<Uri, int> _obsCount = new();
        private readonly IWorkerMetricsStore _metricsStore;
        private readonly HedgePolicy _hedgePolicy;

        public AudioGenerator(ILogger<OpenAIRunner> logger, SystemParams systemParams, IWorkerMetricsStore? metricsStore = null)
        {
            _logger = logger;

            // Build _workers from either the list or the legacy single URL
            IEnumerable<string> candidates =
                (systemParams.AudioServiceUrls != null && systemParams.AudioServiceUrls.Count > 0)
                    ? systemParams.AudioServiceUrls
                    : (!string.IsNullOrWhiteSpace(systemParams.AudioServiceUrl)
                        ? new[] { systemParams.AudioServiceUrl }
                        : Enumerable.Empty<string>());

            var workerList = new List<Uri>();
            foreach (var s in candidates)
            {
                if (string.IsNullOrWhiteSpace(s)) continue;
                var trimmed = s.Trim();

                if (Uri.TryCreate(trimmed, UriKind.Absolute, out var u) &&
                    (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
                {
                    workerList.Add(u);
                }
            }

            _workers = workerList
                .Distinct()
                .ToArray();

            if (_workers.Length == 0)
                throw new InvalidOperationException("No AudioServiceUrls configured.");

            _logger.LogInformation("TTS workers: {Workers}", string.Join(", ", _workers.Select(u => u.ToString())));

            // Load persisted worker latency metrics
            _metricsStore = metricsStore ?? new FileWorkerMetricsStore(FileWorkerMetricsStore.DefaultPath());
            var loaded = _metricsStore.LoadAll();
            foreach (var kvp in loaded)
            {
                if (Uri.TryCreate(kvp.Key, UriKind.Absolute, out var u) && _workers.Contains(u))
                {
                    _metrics[u] = WorkerMetrics.FromRecord(kvp.Value);
                    // if persisted data existed, treat as at least a few observations
                    _obsCount[u] = Math.Max(_obsCount.GetOrAdd(u, 0), 3);
                }
            }

            // Less aggressive defaults to cut hedges
            _hedgePolicy = new HedgePolicy
            {
                MinHedgeDelayMs = 3000,
                MaxHedgeDelayMs = 9000,
                DelayFactor = 1.0,
                AggressiveFirstN = 0,
                AggressiveFactor = 0.9,
                NoHedgeUnderExpectedMs = 4000,
                FirstChunkSloMs = 5000,
                LaterChunkSloMs = 6500,
                ColdOverheadGuessMs = 1200,
                ColdPerCharGuessMs = 45
            };
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

            // 1) First chunk sync
            var (w0, f0) = await GenerateOnBestWorker(chunks[0]);
            urls[0] = string.IsNullOrEmpty(f0) ? "" : BuildFileUrl(w0, f0);

            // 2) Prefetch the rest, bounded
            int par = ParallelismFor(chunks.Count - 1);
            using var gate = new SemaphoreSlim(par);
            var tasks = new Task[chunks.Count - 1];

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

            for (int i = 0; i < tasks.Length; i++)
                await tasks[i];

            return urls.Where(u => !string.IsNullOrEmpty(u)).ToList();
        }

        public async IAsyncEnumerable<string> StreamAudioInOrder(
            string text,
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            var chunks = GetChunksFromText(text, 500);
            int N = chunks.Count;
            if (N == 0) yield break;

            int W = Math.Max(1, Math.Min(_workers.Length, N));

            // Per-response hedge budget (max 1 per 6 chunks, at least 1)
            int hedgeBudget = Math.Max(1, N / 6);
            int hedgesUsed = 0;

            int nextToEmit = 0;
            var buf = new Dictionary<int, string>(capacity: W * 2);
            var lastLaunched = new int[W];

            async Task<(int idx, string url)> Launch(int idx)
            {
                if (idx >= N) return (idx, "");

                string textFrag = chunks[idx];
                int chunkLen = textFrag.Length;

                const int PREVIEW_MAX = 160;
                string preview = textFrag.Length <= PREVIEW_MAX
                    ? textFrag
                    : textFrag.Substring(0, PREVIEW_MAX) + "…";
                preview = preview.Replace("\r", " ").Replace("\n", " ");

                string hash;
                {
                    Span<byte> h = stackalloc byte[32];
                    SHA256.HashData(Encoding.UTF8.GetBytes(textFrag), h);
                    hash = Convert.ToHexString(h.Slice(0, 6));
                }

                var preferred = _workers[idx % W];

                // Choose an alternate by lowest expected time among healthy others
                var healthyAlts = _workers.Where(w => w != preferred && !IsCircuitOpen(w)).ToArray();
                bool hasHealthyAlt = healthyAlts.Length > 0;

                double expPrimary = ExpectedMs(preferred, chunkLen);
                double expAltBest = hasHealthyAlt
                    ? healthyAlts.Min(a => ExpectedMs(a, chunkLen))
                    : double.PositiveInfinity;

                // Hedge gating: make hedges rare and useful
                const int MinChunkToHedge = 60;      // do not hedge tiny chunks
                const double MinRelGain = 0.80;      // require >=20% faster alt
                bool enoughObs = _obsCount.TryGetValue(preferred, out var seen) && seen >= 3;

                bool allowHedge =
                    hasHealthyAlt &&
                    chunkLen >= MinChunkToHedge &&
                    expPrimary >= _hedgePolicy.NoHedgeUnderExpectedMs &&
                    expAltBest < expPrimary * MinRelGain &&
                    enoughObs &&
                    hedgesUsed < hedgeBudget;

                int hedgeDelayMs = allowHedge
                    ? _hedgePolicy.ComputeDelayMs(idx, chunkLen,
                        _metrics.TryGetValue(preferred, out var m) ? m : null,
                        hasHealthyAlt)
                    : int.MaxValue;

                using var t1Cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                using var t2Cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

                var sw = Stopwatch.StartNew();

                _logger.LogDebug(
                    "TTS LAUNCH idx={Idx} len={Len} hash={Hash} pref={Pref} expPrimaryMs={ExpP:0} expAltBestMs={ExpA:0} allowHedge={Allow} hedgeDelayMs={HedgeDelay} text='{Text}'",
                    idx, chunkLen, hash, preferred, expPrimary, expAltBest, allowHedge, (hedgeDelayMs == int.MaxValue ? -1 : hedgeDelayMs), preview);

                var t1 = GenerateOnPreferredThenOthers(textFrag, preferred, t1Cts.Token);

                if (hedgeDelayMs == int.MaxValue)
                {
                    var (w, f) = await t1;

                    _logger.LogInformation(
                        "TTS DONE idx={Idx} len={Len} hash={Hash} worker={Worker} hedged={Hedged} winner=primary durMs={Dur} text='{Text}'",
                        idx, chunkLen, hash, w, false, sw.ElapsedMilliseconds, preview);

                    return (idx, string.IsNullOrEmpty(f) ? "" : BuildFileUrl(w, f));
                }

                var delay = Task.Delay(hedgeDelayMs, ct);
                if (await Task.WhenAny(t1, delay) == t1)
                {
                    var (w, f) = await t1;

                    _logger.LogInformation(
                        "TTS DONE idx={Idx} len={Len} hash={Hash} worker={Worker} hedged={Hedged} winner=primary durMs={Dur} text='{Text}'",
                        idx, chunkLen, hash, w, false, sw.ElapsedMilliseconds, preview);

                    return (idx, string.IsNullOrEmpty(f) ? "" : BuildFileUrl(w, f));
                }

                // Start hedge
                int start = Array.IndexOf(_workers, preferred);
                var alt = _workers[(start + 1) % _workers.Length];
                hedgesUsed++;

                _logger.LogDebug(
                    "TTS HEDGE START idx={Idx} afterMs={After} hash={Hash} primary={Primary} alt={Alt} text='{Text}'",
                    idx, sw.ElapsedMilliseconds, hash, preferred, alt, preview);

                var t2 = GenerateOnPreferredThenOthers(textFrag, alt, t2Cts.Token);
                var winner = await Task.WhenAny(t1, t2);

                if (winner == t1) t2Cts.Cancel(); else t1Cts.Cancel();

                var (ww, ff) = await winner;

                _logger.LogInformation(
                    "TTS DONE idx={Idx} len={Len} hash={Hash} worker={Worker} hedged={Hedged} winner={Winner} durMs={Dur} text='{Text}'",
                    idx, chunkLen, hash, ww, true, (winner == t1) ? "primary" : "alt", sw.ElapsedMilliseconds, preview);

                return (idx, string.IsNullOrEmpty(ff) ? "" : BuildFileUrl(ww, ff));
            }

            var running = new List<Task<(int idx, string url)>>(W);
            for (int lane = 0; lane < W; lane++)
            {
                running.Add(Launch(lane));
                lastLaunched[lane] = lane;
            }

            void ScheduleNextForLane(int idx)
            {
                int lane = idx % W;
                if (lastLaunched[lane] == idx)
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

                ScheduleNextForLane(idx);

                while (buf.TryGetValue(nextToEmit, out var readyUrl))
                {
                    buf.Remove(nextToEmit);
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
                ct.ThrowIfCancellationRequested();

                var w = _workers[(start + step) % _workers.Length];
                if (IsCircuitOpen(w)) continue;

                var sw = Stopwatch.StartNew();
                try
                {
                    var f = await PostGenerate(w, text, ct);
                    var ms = sw.ElapsedMilliseconds;

                    if (!string.IsNullOrEmpty(f))
                    {
                        var m = _metrics.GetOrAdd(w, _ => new WorkerMetrics());
                        m.ObserveSuccess(text.Length, ms);
                        _metricsStore.Upsert(w, m);
                        _obsCount.AddOrUpdate(w, 1, (_, old) => old + 1);

                        RecordSuccess(w);
                        return (w, f);
                    }

                    RecordFailure(w);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
            }

            // Last resort: ignore circuit, circular order
            for (int step = 0; step < _workers.Length; step++)
            {
                ct.ThrowIfCancellationRequested();

                var w = _workers[(start + step) % _workers.Length];

                var sw = Stopwatch.StartNew();
                try
                {
                    var f = await PostGenerate(w, text, ct);
                    var ms = sw.ElapsedMilliseconds;

                    if (!string.IsNullOrEmpty(f))
                    {
                        var m = _metrics.GetOrAdd(w, _ => new WorkerMetrics());
                        m.ObserveSuccess(text.Length, ms);
                        _metricsStore.Upsert(w, m);
                        _obsCount.AddOrUpdate(w, 1, (_, old) => old + 1);

                        RecordSuccess(w);
                        return (w, f);
                    }

                    RecordFailure(w);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
            }

            return (preferred, "");
        }

        private int ParallelismFor(int workItems)
                => Math.Max(1, Math.Min(_workers.Length, workItems));

        // ----- Core routing & calls -----

        private async Task<(Uri worker, string filename)> GenerateOnBestWorker(string text)
        {
            if (_workers.Length == 1)
            {
                var w = _workers[0];
                var f = await PostGenerate(w, text);
                return (w, f);
            }

            var preferred = PickWorkerConsistent(text);

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

        private Task<string> PostGenerate(Uri worker, string text)
            => PostGenerate(worker, text, CancellationToken.None);

        private async Task<string> PostGenerate(Uri worker, string text, CancellationToken ct)
        {
            try
            {
                var endpoint = new Uri(worker, "generate_audio");
                var payload = JsonSerializer.Serialize(new { text });
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var req = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };

                using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                var body = await res.Content.ReadAsStringAsync(ct);

                if (!res.IsSuccessStatusCode)
                {
                    _logger.LogWarning("TTS {Worker} failed: {Status} {Body}", worker, (int)res.StatusCode, body);
                    return "";
                }

                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty("filename", out var fnEl) ? (fnEl.GetString() ?? "") : "";
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException oce) { _logger.LogWarning(oce, "TTS timeout for {Worker}", worker); return ""; }
            catch (Exception ex) { _logger.LogWarning(ex, "TTS error for {Worker}", worker); return ""; }
        }

        private string BuildFileUrl(Uri worker, string filename)
            => new Uri(worker, $"files/{Uri.EscapeDataString(filename)}").ToString();

        // ----- Consistent hashing & health -----

        private Uri PickWorkerConsistent(string key)
        {
            Span<byte> hash = stackalloc byte[32];
            SHA256.HashData(Encoding.UTF8.GetBytes(key), hash);
            ulong v = BitConverter.ToUInt64(hash.Slice(0, 8));
            var idx = (int)(v % (ulong)_workers.Length);
            return _workers[idx];
        }

        private IEnumerable<Uri> OrderByHealth(Uri first)
        {
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
            _circuits[w] = new Circuit();
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
                    yield return w;
                    continue;
                }
                buf.Add(w);
                len += next;
            }
            if (buf.Count > 0) yield return string.Join(" ", buf);
        }

        private double ExpectedMs(Uri worker, int textLen)
        {
            if (textLen <= 0) textLen = 1;
            if (_metrics.TryGetValue(worker, out var m) && m.HasData)
                return m.ExpectedMs(textLen);

            // cold guess aligned with HedgePolicy
            return _hedgePolicy.ColdOverheadGuessMs + _hedgePolicy.ColdPerCharGuessMs * Math.Max(1, textLen);
        }
    }
}

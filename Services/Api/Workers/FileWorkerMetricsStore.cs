using System;
using System.IO;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.Unicode;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services
{
    public sealed class FileWorkerMetricsStore : IWorkerMetricsStore
    {
        private readonly string _path;
        private readonly object _lock = new();
        private readonly JsonSerializerOptions _json = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        private ConcurrentDictionary<string, WorkerMetricsRecord> _cache;

        public FileWorkerMetricsStore(string path)
        {
            _path = path ?? throw new ArgumentNullException(nameof(path));

            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            _cache = new ConcurrentDictionary<string, WorkerMetricsRecord>(
                LoadFromDiskInternal(), StringComparer.OrdinalIgnoreCase);
        }

        public IReadOnlyDictionary<string, WorkerMetricsRecord> LoadAll() => _cache;

        public void Upsert(Uri worker, WorkerMetrics metrics)
        {
            if (worker is null) throw new ArgumentNullException(nameof(worker));
            if (metrics is null) throw new ArgumentNullException(nameof(metrics));

            var key = worker.AbsoluteUri;
            _cache[key] = metrics.ToRecord();
            Persist();
        }

        private Dictionary<string, WorkerMetricsRecord> LoadFromDiskInternal()
        {
            try
            {
                if (!File.Exists(_path)) return new();
                using var fs = File.OpenRead(_path);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, WorkerMetricsRecord>>(fs, _json);
                return loaded ?? new();
            }
            catch
            {
                return new();
            }
        }

        private void Persist()
        {
            lock (_lock)
            {
                var tmp = _path + ".tmp";
                using (var fs = File.Create(tmp))
                {
                    JsonSerializer.Serialize(fs, _cache, _json);
                    fs.Flush(true);
                }

                try
                {
                    if (File.Exists(_path))
                        File.Replace(tmp, _path, null); // atomic where supported
                    else
                        File.Move(tmp, _path);
                }
                catch (PlatformNotSupportedException)
                {
                    // Fallback for filesystems without Replace
                    SafeMoveOverwriting(tmp, _path);
                }
                catch (IOException)
                {
                    // Fallback on IO contention: overwrite by move
                    SafeMoveOverwriting(tmp, _path);
                }
            }
        }

        private static void SafeMoveOverwriting(string source, string dest)
        {
            try
            {
                if (File.Exists(dest)) File.Delete(dest);
            }
            catch { /* best effort */ }

            File.Move(source, dest);
        }

        public static string DefaultPath()
        {
            var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var dir = Path.Combine(baseDir, "NetworkMonitor", "LLM", "state");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "tts-worker-metrics.json");
        }
    }
}

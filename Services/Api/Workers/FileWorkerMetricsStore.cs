using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.Unicode;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System;

namespace NetworkMonitor.LLM.Services
{


    public sealed class WorkerMetricsRecord
    {
        public bool HasData { get; set; }
        public double OverheadMs { get; set; }
        public double MsPerChar { get; set; }
    }

    public interface IWorkerMetricsStore
    {
        // Load all persisted metrics (keyed by absolute worker URI string).
        IReadOnlyDictionary<string, WorkerMetricsRecord> LoadAll();

        // Insert or update one worker’s metrics. Implementations must be thread-safe.
        void Upsert(Uri worker, WorkerMetrics metrics);
    }


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
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            _cache = new ConcurrentDictionary<string, WorkerMetricsRecord>(
                LoadFromDiskInternal(), StringComparer.OrdinalIgnoreCase);
        }

        public IReadOnlyDictionary<string, WorkerMetricsRecord> LoadAll()
            => _cache; // already loaded at construction

        public void Upsert(Uri worker, WorkerMetrics metrics)
        {
            if (worker is null) throw new ArgumentNullException(nameof(worker));
            if (metrics is null) throw new ArgumentNullException(nameof(metrics));

            var key = worker.AbsoluteUri;
            var rec = metrics.ToRecord();

            _cache[key] = rec;
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
                // Corrupt or unreadable file; start fresh.
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

                if (File.Exists(_path))
                    File.Replace(tmp, _path, destinationBackupFileName: null); // fix here
                else
                    File.Move(tmp, _path);
            }
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

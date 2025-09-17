using System;

namespace NetworkMonitor.LLM.Services
{
    public sealed class WorkerMetrics
    {
        private const double Alpha = 0.2; // EWMA smoothing
        private double _msPerChar;
        private double _overheadMs;
        private bool _has;
        private readonly object _lock = new();

        public void ObserveSuccess(int textLen, long elapsedMs)
        {
            if (textLen <= 0) textLen = 1;
            var perChar = (double)elapsedMs / textLen;

            lock (_lock)
            {
                if (!_has)
                {
                    _msPerChar = perChar;
                    _overheadMs = 0;
                    _has = true;
                    return;
                }

                _msPerChar = Alpha * perChar + (1 - Alpha) * _msPerChar;

                var residual = Math.Max(0.0, elapsedMs - _msPerChar * textLen);
                _overheadMs = Alpha * residual + (1 - Alpha) * _overheadMs;
            }
        }

        public double ExpectedMs(int textLen)
        {
            if (!_has) return double.NaN;
            if (textLen <= 0) textLen = 1;
            lock (_lock) { return _overheadMs + _msPerChar * textLen; }
        }

        public bool HasData { get { lock (_lock) return _has; } }

        // Persistence helpers
        public WorkerMetricsRecord ToRecord()
        {
            lock (_lock)
            {
                return new WorkerMetricsRecord
                {
                    HasData = _has,
                    OverheadMs = _overheadMs,
                    MsPerChar = _msPerChar
                };
            }
        }

        public static WorkerMetrics FromRecord(WorkerMetricsRecord rec)
        {
            var m = new WorkerMetrics();
            if (rec is null || !rec.HasData) return m;
            lock (m._lock)
            {
                m._has = true;
                m._overheadMs = rec.OverheadMs;
                m._msPerChar = rec.MsPerChar;
            }
            return m;
        }
    }
}

using System;
namespace NetworkMonitor.LLM.Services
{
    internal sealed class HedgePolicy
    {
        // Bounds to avoid hyper-aggressive or useless hedges
        public int MinHedgeDelayMs { get; init; } = 1200;
        public int MaxHedgeDelayMs { get; init; } = 5000;

        // Multiply expected latency by this factor to schedule hedge
        public double DelayFactor { get; init; } = 0.9;

        // Slightly more aggressive only for first N chunks
        public int AggressiveFirstN { get; init; } = 1;
        public double AggressiveFactor { get; init; } = 0.7;

        // Skip hedging if we predict fast anyway
        public int NoHedgeUnderExpectedMs { get; init; } = 900;

        // Soft SLOs: if expected ≤ SLO, skip hedge
        public int FirstChunkSloMs { get; init; } = 2000;
        public int LaterChunkSloMs { get; init; } = 3500;

        // Cold-start guess when we have no data for a worker yet
        public int ColdOverheadGuessMs { get; init; } = 2200;
        public int ColdPerCharGuessMs { get; init; } = 12;

        public int ComputeDelayMs(
            int chunkIndex,
            int textLen,
            WorkerMetrics metricsOrNull,
            bool hasHealthyAlternate)
        {
            if (!hasHealthyAlternate) return int.MaxValue; // no hedge possible

            double expected = metricsOrNull is { HasData: true }
                ? metricsOrNull.ExpectedMs(textLen)
                : ColdOverheadGuessMs + ColdPerCharGuessMs * Math.Max(1, textLen);

            if (expected < NoHedgeUnderExpectedMs) return int.MaxValue;

            // If primary is likely to meet SLO, skip hedging
            int slo = chunkIndex == 0 ? FirstChunkSloMs : LaterChunkSloMs;
            if (expected <= slo) return int.MaxValue;

            double factor = chunkIndex < AggressiveFirstN ? AggressiveFactor : DelayFactor;
            int delay = (int)Math.Clamp(expected * factor, MinHedgeDelayMs, MaxHedgeDelayMs);
            return delay;
        }

        public static HedgePolicy Default { get; } = new HedgePolicy();
    }
}

using System;

namespace NetworkMonitor.LLM.Services
{
    internal sealed class HedgePolicy
    {
        // Less aggressive defaults to reduce unnecessary hedging
        public int MinHedgeDelayMs { get; init; } = 3000;
        public int MaxHedgeDelayMs { get; init; } = 9000;

        // Use full expected latency for scheduling
        public double DelayFactor { get; init; } = 1.0;

        // No extra aggressiveness for the first chunks
        public int AggressiveFirstN { get; init; } = 0;
        public double AggressiveFactor { get; init; } = 0.9;

        // Skip hedging if we predict the primary will be fast anyway
        public int NoHedgeUnderExpectedMs { get; init; } = 4000;

        // Softer SLOs
        public int FirstChunkSloMs { get; init; } = 5000;
        public int LaterChunkSloMs { get; init; } = 6500;

        // Cold-start guesses aligned with observed behavior
        public int ColdOverheadGuessMs { get; init; } = 1200;
        public int ColdPerCharGuessMs { get; init; } = 45;

        public int ComputeDelayMs(
            int chunkIndex,
            int textLen,
            WorkerMetrics? metricsOrNull,
            bool hasHealthyAlternate)
        {
            if (!hasHealthyAlternate) return int.MaxValue; // no hedge possible

            double expected = (metricsOrNull is { HasData: true })
                ? metricsOrNull.ExpectedMs(textLen)
                : ColdOverheadGuessMs + ColdPerCharGuessMs * Math.Max(1, textLen);

            if (expected < NoHedgeUnderExpectedMs) return int.MaxValue;

            int slo = chunkIndex == 0 ? FirstChunkSloMs : LaterChunkSloMs;
            if (expected <= slo) return int.MaxValue;

            double factor = chunkIndex < AggressiveFirstN ? AggressiveFactor : DelayFactor;
            int delay = (int)Math.Clamp(expected * factor, MinHedgeDelayMs, MaxHedgeDelayMs);
            return delay;
        }

        public static HedgePolicy Default { get; } = new HedgePolicy();
    }
}

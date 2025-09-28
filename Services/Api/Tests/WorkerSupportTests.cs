using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class AudioGeneratorTests
{
    [Fact]
    public void GetChunksFromText_RespectsParagraphsAndWordLimit()
    {
        var generator = CreateGenerator();
        var text = "First paragraph.\n\nSecond paragraph with several words spread across lines to test wrapping.";

        var chunks = generator.GetChunksFromText(text, maxLength: 25);

        Assert.NotEmpty(chunks);
        Assert.Equal("First paragraph.", chunks[0]);
        Assert.All(chunks, chunk => Assert.True(chunk.Length <= 25 || chunk.Split(' ').Any(word => word.Length > 25)));
    }

    private static AudioGenerator CreateGenerator()
    {
        var logger = new Mock<ILogger<OpenAIRunner>>();
        var systemParams = new SystemParams
        {
            AudioServiceUrls = new List<string> { "https://tts.example.com/" }
        };
        var metricsStore = new Mock<IWorkerMetricsStore>();
        metricsStore.Setup(m => m.LoadAll()).Returns(new Dictionary<string, WorkerMetricsRecord>());

        return new AudioGenerator(logger.Object, systemParams, metricsStore.Object);
    }
}

public class FileWorkerMetricsStoreTests
{
    [Fact]
    public void Upsert_PersistsMetrics()
    {
        var path = Path.Combine(Path.GetTempPath(), $"metrics-{Guid.NewGuid():N}.json");
        try
        {
            var store = new FileWorkerMetricsStore(path);
            Assert.Empty(store.LoadAll());

            var metrics = new WorkerMetrics();
            metrics.ObserveSuccess(50, 1000);

            store.Upsert(new Uri("https://tts.example.com/"), metrics);

            var reloaded = new FileWorkerMetricsStore(path);
            var all = reloaded.LoadAll();
            Assert.True(all.ContainsKey("https://tts.example.com/"));
            Assert.True(all["https://tts.example.com/"].HasData);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}

public class HedgePolicyTests
{
    [Fact]
    public void ComputeDelayMs_NoAlternate_ReturnsMax()
    {
        var policy = new HedgePolicy();
        var delay = policy.ComputeDelayMs(0, 100, null, hasHealthyAlternate: false);
        Assert.Equal(int.MaxValue, delay);
    }

    [Fact]
    public void ComputeDelayMs_WithMetrics_ReturnsClampedDelay()
    {
        var metrics = new WorkerMetrics();
        metrics.ObserveSuccess(120, 9000);

        var policy = new HedgePolicy
        {
            MinHedgeDelayMs = 500,
            MaxHedgeDelayMs = 4000,
            NoHedgeUnderExpectedMs = 2000
        };

        var delay = policy.ComputeDelayMs(1, 120, metrics, hasHealthyAlternate: true);

        Assert.InRange(delay, policy.MinHedgeDelayMs, policy.MaxHedgeDelayMs);
    }
}

public class WorkerMetricsTests
{
    [Fact]
    public void ObserveSuccess_ComputesExpectedLatency()
    {
        var metrics = new WorkerMetrics();
        Assert.True(double.IsNaN(metrics.ExpectedMs(10)));

        metrics.ObserveSuccess(100, 5000);

        Assert.True(metrics.HasData);
        var expected = metrics.ExpectedMs(50);
        Assert.True(expected > 0);

        var record = metrics.ToRecord();
        var cloned = WorkerMetrics.FromRecord(record);
        Assert.False(double.IsNaN(cloned.ExpectedMs(10)));
        Assert.InRange(cloned.ExpectedMs(50), expected * 0.5, expected * 1.5);
    }
}

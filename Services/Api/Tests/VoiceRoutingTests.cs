using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetworkMonitor.Objects;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class VoiceRoutingTests
{
    [Fact]
    public void HostnamePartitionsWorkersWithoutOverlap()
    {
        var standard = new Uri("https://transcribe.readyforquantum.com");
        var standard2 = new Uri("https://transcribe2.readyforquantum.com");
        var hal = new Uri("https://HALTRANSCRIBE.readyforquantum.com");
        var misleadingPath = new Uri("https://standard.example/haltranscribe.readyforquantum.com/");
        var workers = new[] { standard, standard2, hal, misleadingPath, hal };
        Assert.Equal(new[] { hal }, AudioGenerator.SelectWorkers(workers, true));
        Assert.Equal(new[] { standard, standard2, misleadingPath }, AudioGenerator.SelectWorkers(workers, false));
    }

    [Theory]
    [InlineData("hal")]
    [InlineData("hal9000")]
    [InlineData("halsimple")]
    [InlineData("hal9000simple")]
    [InlineData("hal_simple")]
    [InlineData("hal9000_simple")]
    [InlineData(" HAL9000 ")]
    public void AllHalConfigurationRolesUseHalVoice(string role)
    {
        var settings = new MLParams { PrimaryMonitorRole = role };
        Assert.True(MonitorSessionRole.UsesHalVoice(Resolve(settings, "conversation_user_TestLLM")));
    }

    [Fact]
    public void SessionAndRunnerSettingsHaveSamePrecedenceAsBuilderSelection()
    {
        var settings = new MLParams { PrimaryMonitorRole = "hal9000" };
        settings.PrimaryMonitorRoleByRunner["TestLLM"] = "standard";
        Assert.False(MonitorSessionRole.UsesHalVoice(Resolve(settings, "conversation_user_TestLLM")));
        Assert.True(MonitorSessionRole.UsesHalVoice(Resolve(settings, "conversation:halsimple_user_TestLLM")));
        settings.PrimaryMonitorRoleByRunner["TestLLM"] = "hal9000simple";
        Assert.False(MonitorSessionRole.UsesHalVoice(Resolve(settings, "conversation:standard_user_TestLLM")));
    }

    [Fact]
    public async Task MissingHalPoolDoesNotFallBackToStandardWorker()
    {
        var generator = CreateGenerator("https://transcribe.readyforquantum.com");
        var hal = generator.ForVoice(true);
        Assert.Same(hal, generator.ForVoice(true));
        Assert.Same(generator, generator.ForVoice(false));
        await using var stream = hal.StreamAudioInOrder("Hello Dave.").GetAsyncEnumerator();
        await Assert.ThrowsAsync<InvalidOperationException>(() => stream.MoveNextAsync().AsTask());
    }

    [Fact]
    public async Task MissingStandardPoolDoesNotUseHalWorker()
    {
        var generator = CreateGenerator("https://haltranscribe.readyforquantum.com");
        await using var stream = generator.StreamAudioInOrder("Hello.").GetAsyncEnumerator();
        await Assert.ThrowsAsync<InvalidOperationException>(() => stream.MoveNextAsync().AsTask());
    }

    private static string? Resolve(MLParams settings, string sessionId) => MonitorSessionRole.Resolve(
        "monitor", new SystemParams { UserFacingServiceId = "monitor" }, settings, "TestLLM", sessionId);

    private static AudioGenerator CreateGenerator(params string[] urls)
    {
        var store = new Mock<IWorkerMetricsStore>();
        store.Setup(s => s.LoadAll()).Returns(new Dictionary<string, WorkerMetricsRecord>());
        return new AudioGenerator(NullLogger<OpenAIRunner>.Instance,
            new SystemParams { AudioServiceUrls = urls.ToList() }, store.Object);
    }
}

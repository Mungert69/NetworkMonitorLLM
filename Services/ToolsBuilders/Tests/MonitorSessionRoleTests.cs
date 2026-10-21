using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetworkMonitor.Objects;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class MonitorSessionRoleTests
{
    [Theory]
    [InlineData("conversation:hal_user_TurboLLM", "hal9000")]
    [InlineData("conversation:hal9000_user_TestLLM", "hal9000")]
    [InlineData("conversation:Hal9000_user_HugLLM", "hal9000")]
    [InlineData("conversation:hal9000simple_user_TurboLLM", "hal9000simple")]
    [InlineData("conversation:halsimple_user_TurboLLM", "hal9000simple")]
    [InlineData("conversation:standard_user_TurboLLM", "standard")]
    [InlineData("conversation:simple_user_TurboLLM", "simple")]
    [InlineData("conversation:hal9000", "hal9000")]
    [InlineData("conversation_user_TurboLLM", null)]
    [InlineData("conversation_user:hal9000_TurboLLM", null)]
    [InlineData("conversation_user_runner:hal9000", null)]
    [InlineData("conversation:unknown_user_TurboLLM", null)]
    [InlineData(":hal9000_user_TurboLLM", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void ReadsOnlyRecognizedRoleInConversation(string? sessionId, string? expected)
    {
        Assert.Equal(expected, MonitorSessionRole.FromSessionId(sessionId));
    }

    [Theory]
    [InlineData("hal", typeof(Hal9000MonitorToolsBuilder))]
    [InlineData("hal9000", typeof(Hal9000MonitorToolsBuilder))]
    [InlineData("hal9000simple", typeof(Hal9000MonitorSimpleToolsBuilder))]
    [InlineData("standard", typeof(MonitorToolsBuilder))]
    [InlineData("simple", typeof(MonitorSimpleToolsBuilder))]
    public void ExplicitSessionRoleOverridesRunnerAndGlobalSettings(string role, System.Type expected)
    {
        var settings = new MLParams { PrimaryMonitorRole = "simple" };
        settings.PrimaryMonitorRoleByRunner["TurboLLM"] = "hal9000simple";
        var builder = CreateFactory(settings).Create("monitor", runnerType: "TurboLLM",
            sessionId: $"conversation:{role}_user_TurboLLM");
        Assert.IsType(expected, builder);
    }

    [Theory]
    [InlineData("conversation_user_TurboLLM")]
    [InlineData("conversation:unknown_user_TurboLLM")]
    public void UnmarkedOrUnknownRolePreservesRunnerConfiguration(string sessionId)
    {
        var settings = new MLParams { PrimaryMonitorRole = "hal9000" };
        settings.PrimaryMonitorRoleByRunner["TurboLLM"] = "simple";
        Assert.IsType<MonitorSimpleToolsBuilder>(CreateFactory(settings).Create(
            "monitor", runnerType: "TurboLLM", sessionId: sessionId));
    }

    [Theory]
    [InlineData("hal9000_simple")]
    [InlineData("hal_simple")]
    [InlineData("hal9000simple")]
    public void ExistingAndNewSimpleConfigurationNamesWork(string role)
    {
        Assert.IsType<Hal9000MonitorSimpleToolsBuilder>(CreateFactory(
            new MLParams { PrimaryMonitorRole = role }).Create("monitor"));
    }

    [Fact]
    public void SessionRoleDoesNotChangeExpertBuilder()
    {
        Assert.IsType<MemoryExpertToolsBuilder>(CreateFactory(new MLParams()).Create(
            "memory", sessionId: "conversation:hal9000_user_TurboLLM"));
    }

    [Fact]
    public void SessionRoleDoesNotChangeNonPrimaryMonitorService()
    {
        var factory = new ToolsBuilderFactory(NullLogger<ToolsBuilderFactory>.Instance,
            Mock.Of<IFunctionDefinitionRegistry>(), new MLParams(),
            new SystemParams { UserFacingServiceId = "other" });
        Assert.IsType<MonitorToolsBuilder>(factory.Create(
            "monitor", sessionId: "conversation:hal9000_user_TurboLLM"));
    }

    [Fact]
    public void UnmarkedSessionUsesGlobalRoleWhenNoRunnerOverrideExists()
    {
        Assert.IsType<Hal9000MonitorToolsBuilder>(CreateFactory(
            new MLParams { PrimaryMonitorRole = "hal9000" }).Create(
                "monitor", runnerType: "TurboLLM", sessionId: "conversation_user_TurboLLM"));
    }

    [Fact]
    public void LocalPromptFilesSeparateRolesAndPreserveDefaultName()
    {
        Assert.Equal("prompt_run", MonitorSessionRole.PromptFileName("prompt_run", "conversation_user_TestLLM"));
        Assert.Equal("prompt_run.hal9000", MonitorSessionRole.PromptFileName("prompt_run", "conversation:hal_user_TestLLM"));
        Assert.Equal("prompt_run.hal9000simple", MonitorSessionRole.PromptFileName("prompt_run", "conversation:hal9000simple_user_TestLLM"));
    }

    private static ToolsBuilderFactory CreateFactory(MLParams settings) => new(
        NullLogger<ToolsBuilderFactory>.Instance,
        Mock.Of<IFunctionDefinitionRegistry>(), settings,
        new SystemParams { UserFacingServiceId = "monitor" });
}

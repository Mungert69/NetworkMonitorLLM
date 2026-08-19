using System.Linq;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LivePenetrationToolsBuilderTests
{
    [Fact]
    public void Builder_ExposesOnlyInteractiveConsole()
    {
        var tool = Assert.Single(new LivePenetrationExpertToolsBuilder().Tools);
        Assert.Equal("interact_msfconsole", tool.Function!.Name);
        Assert.Contains("outputTruncated", tool.Function.Description);
        Assert.Contains("bounded beginning and latest end", tool.Function.Description);
        Assert.Contains("agent_location", tool.Function.Parameters!.Required!);
        Assert.Equal(
            new[] { "write", "read", "detach", "interrupt", "close" },
            tool.Function.Parameters.Properties!["control"].Enum);
    }

    [Fact]
    public void Prompt_ExplainsContinuityAndMetasploitWorkflow()
    {
        var prompt = Assert.Single(new LivePenetrationExpertToolsBuilder()
            .GetSystemPrompt("2026-08-17T00:00:00Z", new LLMServiceObj(), "TestLLM")).Content;

        Assert.Contains("exactly that same value", prompt);
        Assert.Contains("show missing", prompt);
        Assert.Contains("Meterpreter", prompt);
        Assert.Contains("control close", prompt);
        Assert.Contains("commandComplete is false", prompt);
        Assert.Contains("outputTruncated does not mean", prompt);
        Assert.Contains("Avoid broad listings such as show payloads", prompt);
        Assert.DoesNotContain("When has_more is true", prompt);
    }
}

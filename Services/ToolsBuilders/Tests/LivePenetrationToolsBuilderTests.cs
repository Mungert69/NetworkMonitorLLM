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
        Assert.Contains("attached shell or Meterpreter prompt", tool.Function.Description);
        Assert.Contains("session_write and session_read", tool.Function.Description);
        Assert.Contains("structured sessions", tool.Function.Description);
        Assert.Contains("agent_location", tool.Function.Parameters!.Required!);
        Assert.Contains("Exactly one command", tool.Function.Parameters.Properties!["input"].Description);
        Assert.Contains("Do not batch commands with semicolons", tool.Function.Parameters.Properties["input"].Description);
        Assert.Contains("does not terminate", tool.Function.Parameters.Properties["control"].Description);
        Assert.Contains("session_stop", tool.Function.Parameters.Properties["control"].Description);
        Assert.Contains("structured sessions", tool.Function.Parameters.Properties["session_id"].Description);
        Assert.Equal(
            new[]
            {
                "write", "read", "detach", "interrupt", "close",
                "session_list", "session_write", "session_read", "session_detach", "session_stop"
            },
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
        Assert.Contains("commandComplete false", prompt);
        Assert.Contains("outputTruncated does not mean", prompt);
        Assert.Contains("Avoid unscoped listings such as show payloads", prompt);
        Assert.Contains("Send exactly one command", prompt);
        Assert.Contains("Never batch commands with semicolons", prompt);
        Assert.Contains("show missing, and run as separate", prompt);
        Assert.Contains("confirmed session is different", prompt);
        Assert.Contains("Structured sessions, interactionMode", prompt);
        Assert.Contains("do not use console commands such as sessions -i", prompt);
        Assert.Contains("session_write with that session_id", prompt);
        Assert.Contains("session_stop to terminate", prompt);
        Assert.Contains("port-only exploit search is normally too broad", prompt);
        Assert.Contains("module-scoped show payloads", prompt);
        Assert.Contains("Maintain an evidence ledger", prompt);
        Assert.Contains("blank getg result", prompt);
        Assert.Contains("session_detach and legacy detach preserve", prompt);
        Assert.Contains("Do not equate detached with terminated", prompt);
        Assert.DoesNotContain("When has_more is true", prompt);
    }
}

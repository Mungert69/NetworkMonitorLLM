using System.Collections.Generic;
using System.Linq;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class MonitorToolsTests
{
    [Fact]
    public void GetSystemPrompt_ExplainsExpertBoundariesAndDelegationRules()
    {
        var builder = new MonitorToolsBuilder();

        var prompt = Assert.Single(builder.GetSystemPrompt(
            "2026-08-03T12:00:00Z",
            new LLMServiceObj(),
            "TestLLM")).Content;

        Assert.Contains("ongoing monitoring lifecycle and telemetry", prompt);
        Assert.Contains("defensive one-time network and TLS assessment", prompt);
        Assert.Contains("authorized adversarial testing", prompt);
        Assert.Contains("Command processors are explicit, run-once jobs", prompt);
        Assert.Contains("Connects are thin checks that run periodically", prompt);
        Assert.Contains("Experts are separate LLMs and do not see this conversation", prompt);
        Assert.Contains("Memory is not live host telemetry", prompt);
        Assert.Contains("Do not present accepted or queued work as completed", prompt);
    }

    [Fact]
    public void GetSystemPrompt_OnlyDescribesPrebuiltFlowsWhenTheyAreAvailable()
    {
        var withoutFlows = Assert.Single(new MonitorToolsBuilder().GetSystemPrompt(
            "2026-08-03T12:00:00Z", new LLMServiceObj(), "TestLLM")).Content;
        var withFlowsBuilder = new MonitorToolsBuilder(enableAgentFlow: true);
        var withFlows = Assert.Single(withFlowsBuilder.GetSystemPrompt(
            "2026-08-03T12:00:00Z", new LLMServiceObj(), "TestLLM")).Content;

        Assert.DoesNotContain("call_security_basic_flow:", withoutFlows);
        Assert.Contains("call_security_basic_flow:", withFlows);
        Assert.DoesNotContain("call_security_expert:", withFlows);
        Assert.Contains("call_security_basic_flow", withFlowsBuilder.Tools.Select(tool => tool.Function?.Name));
    }

    [Fact]
    public void BuildAddHostFunction_ExposesEverySupportedHostConfigurationField()
    {
        var function = MonitorTools.BuildAddHostFunction();

        Assert.NotNull(function.Parameters?.Properties);
        Assert.True(new HashSet<string>
        {
            "detail_response", "address", "endpoint", "port", "username", "password",
            "args", "timeout", "skip_cycles", "email", "agent_location"
        }.SetEquals(function.Parameters!.Properties!.Keys));
        Assert.Equal("number", function.Parameters.Properties["skip_cycles"].Type);
    }

    [Fact]
    public void BuildEditHostFunction_ExposesEverySupportedHostConfigurationField()
    {
        var function = MonitorTools.BuildEditHostFunction();

        Assert.NotNull(function.Parameters?.Properties);
        Assert.True(new HashSet<string>
        {
            "detail_response", "auth_key", "id", "enabled", "address", "endpoint", "port",
            "username", "password", "args", "timeout", "skip_cycles", "hidden", "agent_location"
        }.SetEquals(function.Parameters!.Properties!.Keys));
        Assert.Equal("number", function.Parameters.Properties["skip_cycles"].Type);
    }
}

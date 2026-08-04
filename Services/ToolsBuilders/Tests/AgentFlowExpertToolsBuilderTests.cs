using System;
using System.Linq;
using System.IO;
using System.Text.Json;
using Moq;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class AgentFlowExpertToolsBuilderTests
{
    [Fact]
    public void GetSystemPrompt_UsesTheDeployedCanonicalAgentGraphSchema()
    {
        var registry = new Mock<IFunctionDefinitionRegistry>();
        registry.Setup(value => value.GetFilteredFunctionCatalogJson(true)).Returns("[]");
        var builder = new AgentFlowExpertToolsBuilder(registry.Object);

        var prompt = Assert.Single(builder.GetSystemPrompt(
            "2026-08-04T00:00:00Z", new LLMServiceObj(), "TestLLM")).Content
            ?? throw new InvalidOperationException("Agent-flow system prompt was empty.");
        var schemaPath = Path.Combine(AppContext.BaseDirectory, "Schemas", "agent_schema.json");
        var schema = File.ReadAllText(schemaPath).Trim();

        Assert.Contains(schema, prompt);
        Assert.Contains("runtimeInputs", prompt);
        Assert.True(prompt.IndexOf("4. PROMPT AND PLACEHOLDER RULES", StringComparison.Ordinal) <
                    prompt.IndexOf("7. EXECUTION AND STORAGE", StringComparison.Ordinal));
        Assert.Contains("When composing a flow document for add_agent_flow", prompt);
        Assert.DoesNotContain("Reply with exactly one JSON object", prompt);
    }

    [Fact]
    public void AgentFlowNShot_ContainsAValidFlowCreationToolCall()
    {
        var messages = NShotPromptFactory.GetStaticPrompt("agentflow");
        var addCalls = messages
            .SelectMany(message => message.ToolCalls ?? [])
            .Where(toolCall => toolCall.FunctionCall?.Name == "add_agent_flow")
            .ToList();
        Assert.Equal(3, addCalls.Count);

        var argumentsJson = addCalls[0].FunctionCall?.Arguments
            ?? throw new InvalidOperationException("Agent-flow n-shot did not include tool-call arguments.");
        using var arguments = JsonDocument.Parse(argumentsJson);
        var root = arguments.RootElement;
        Assert.Equal("quick-scan", root.GetProperty("flow_name").GetString());

        var flowJson = root.GetProperty("json").GetString()
            ?? throw new InvalidOperationException("Agent-flow n-shot did not include flow JSON.");
        using var flow = JsonDocument.Parse(flowJson);
        var flowRoot = flow.RootElement;
        Assert.Equal(1, flowRoot.GetProperty("version").GetInt32());
        Assert.Equal("get_targets", flowRoot.GetProperty("startNode").GetString());
        Assert.True(flowRoot.GetProperty("initState").TryGetProperty("agent_location", out _));

        var nodes = flowRoot.GetProperty("nodes").EnumerateArray().ToList();
        Assert.Equal(2, nodes.Count);
        Assert.All(nodes, node => Assert.True(node.TryGetProperty("outputs", out _)));
        Assert.Contains("run_nmap", nodes[1].GetProperty("promptTemplate").GetString());

        var parameterizedArgumentsJson = addCalls[1].FunctionCall?.Arguments
            ?? throw new InvalidOperationException("Parameterized agent-flow n-shot did not include tool-call arguments.");
        using var parameterizedArguments = JsonDocument.Parse(parameterizedArgumentsJson);
        var parameterizedRoot = parameterizedArguments.RootElement;
        Assert.Equal("target-security-recon", parameterizedRoot.GetProperty("flow_name").GetString());

        var parameterizedFlowJson = parameterizedRoot.GetProperty("json").GetString()
            ?? throw new InvalidOperationException("Parameterized agent-flow n-shot did not include flow JSON.");
        using var parameterizedFlow = JsonDocument.Parse(parameterizedFlowJson);
        var parameterizedFlowRoot = parameterizedFlow.RootElement;
        Assert.Equal("target", Assert.Single(parameterizedFlowRoot.GetProperty("runtimeInputs").EnumerateArray()).GetString());
        Assert.False(parameterizedFlowRoot.GetProperty("initState").TryGetProperty("target", out _));

        var parameterizedNodes = parameterizedFlowRoot.GetProperty("nodes").EnumerateArray().ToList();
        Assert.Contains("open_services", parameterizedNodes[1].GetProperty("requires").EnumerateArray().Select(value => value.GetString()));
        Assert.Contains("hardening_guidance", parameterizedNodes[2].GetProperty("requires").EnumerateArray().Select(value => value.GetString()));

        var runCall = Assert.Single(
            messages.SelectMany(message => message.ToolCalls ?? []),
            toolCall => toolCall.FunctionCall?.Name == "run_agent_flow");
        var runArgumentsJson = runCall.FunctionCall?.Arguments
            ?? throw new InvalidOperationException("Agent-flow run n-shot did not include tool-call arguments.");
        using var runArguments = JsonDocument.Parse(runArgumentsJson);
        Assert.Equal("example.com", runArguments.RootElement
            .GetProperty("arguments")
            .GetProperty("target")
            .GetString());

        var retryArgumentsJson = addCalls[2].FunctionCall?.Arguments
            ?? throw new InvalidOperationException("Retry-flow n-shot did not include tool-call arguments.");
        using var retryArguments = JsonDocument.Parse(retryArgumentsJson);
        var retryFlowJson = retryArguments.RootElement.GetProperty("json").GetString()
            ?? throw new InvalidOperationException("Retry-flow n-shot did not include flow JSON.");
        using var retryFlow = JsonDocument.Parse(retryFlowJson);
        var retryFlowRoot = retryFlow.RootElement;
        Assert.Equal(2, retryFlowRoot.GetProperty("initState").GetProperty("RetryLimit").GetInt32());

        var branchNode = retryFlowRoot.GetProperty("nodes").EnumerateArray()
            .Single(node => node.GetProperty("type").GetString() == "branch-llm");
        Assert.False(branchNode.TryGetProperty("outputs", out _));
        var branchNames = branchNode.GetProperty("branches").EnumerateObject()
            .Select(branch => branch.Name)
            .OrderBy(name => name)
            .ToArray();
        Assert.Equal(new[] { "fail", "retry", "success" }, branchNames);
    }
}

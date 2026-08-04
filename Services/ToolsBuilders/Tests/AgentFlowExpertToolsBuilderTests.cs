using System;
using System.IO;
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
            "2026-08-04T00:00:00Z", new LLMServiceObj(), "TestLLM")).Content;
        var schemaPath = Path.Combine(AppContext.BaseDirectory, "Schemas", "agent_schema.json");
        var schema = File.ReadAllText(schemaPath).Trim();

        Assert.Contains(schema, prompt);
        Assert.Contains("runtimeInputs", prompt);
    }
}

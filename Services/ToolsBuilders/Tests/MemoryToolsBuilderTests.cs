using System.Linq;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class MemoryToolsBuilderTests
{
    [Fact]
    public void BuildMemoryQueryFunction_HasSimpleParameters()
    {
        var fn = MemoryQueryTools.BuildMemoryQueryFunction();

        Assert.Equal("execute_query_memory", fn.Name);
        Assert.NotNull(fn.Parameters);
        var parameters = fn.Parameters!;
        Assert.True(parameters.Required!.Contains("message"));
        Assert.True(parameters.Properties!.ContainsKey("message"));
        Assert.False(parameters.Properties.ContainsKey("session_only"));
        Assert.False(parameters.Properties.ContainsKey("index_name"));
        Assert.False(parameters.Properties.ContainsKey("vector_search_mode"));
    }

    [Fact]
    public void BuildMemoryTurnWindowFunction_HasWindowParameters()
    {
        var fn = MemoryQueryTools.BuildMemoryTurnWindowFunction();

        Assert.Equal("get_memory_turn_window", fn.Name);
        Assert.NotNull(fn.Parameters);
        var parameters = fn.Parameters!;
        Assert.True(parameters.Required!.Contains("session_id"));
        Assert.True(parameters.Required.Contains("turn_index"));
        Assert.True(parameters.Properties!.ContainsKey("width_before"));
        Assert.True(parameters.Properties.ContainsKey("width_after"));
    }

    [Fact]
    public void BuildMemoryTurnRangeFunction_HasInclusiveRangeAndContinuationParameters()
    {
        var fn = MemoryQueryTools.BuildMemoryTurnRangeFunction();

        Assert.Equal("get_memory_turn_range", fn.Name);
        Assert.NotNull(fn.Parameters);
        var parameters = fn.Parameters!;
        Assert.Contains("session_id", parameters.Required!);
        Assert.Contains("start_turn_index", parameters.Required);
        Assert.Contains("end_turn_index", parameters.Required);
        Assert.True(parameters.Properties!.ContainsKey("offset"));
        Assert.Contains("20", fn.Description);
    }

    [Fact]
    public void ToolsBuilderFactory_CreateMemory_ReturnsMemoryExpertToolsBuilder()
    {
        var logger = new Mock<ILogger<ToolsBuilderFactory>>();
        var registryLogger = new Mock<ILogger<FunctionDefinitionRegistry>>();
        var rabbitRepo = new Mock<IRabbitRepo>();
        var registry = new FunctionDefinitionRegistry(registryLogger.Object, rabbitRepo.Object);

        var factory = new ToolsBuilderFactory(
            logger.Object,
            registry,
            new MLParams(),
            new SystemParams());

        var builder = factory.Create("memory");

        Assert.IsType<MemoryExpertToolsBuilder>(builder);
        Assert.Contains(builder.Tools, t => t.Function?.Name == "execute_query_memory");
        Assert.Contains(builder.Tools, t => t.Function?.Name == "get_memory_turn_window");
        Assert.Contains(builder.Tools, t => t.Function?.Name == "get_memory_turn_range");
    }

    [Fact]
    public void GetSystemPrompt_SeparatesSemanticAndArchiveRangeRetrieval()
    {
        var prompt = Assert.Single(new MemoryExpertToolsBuilder().GetSystemPrompt(
            "2026-08-11T19:00:00Z", new LLMServiceObj(), "TestLLM")).Content;

        Assert.Contains("ordinary, focused semantic recall", prompt);
        Assert.Contains("get_memory_turn_range", prompt);
        Assert.Contains("at most 20 turns", prompt);
        Assert.Contains("concise, faithful factual summary", prompt);
        Assert.Contains("do not replay a large raw transcript", prompt);
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class MemoryToolsIntegrationTests
{
    [Fact]
    public void MemoryQueryTools_BuildMemoryQueryFunction_ExposesSimpleParameters()
    {
        var fn = MemoryQueryTools.BuildMemoryQueryFunction();

        Assert.Equal("execute_query_memory", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.Contains("message", fn.Parameters.Required);
        Assert.True(fn.Parameters.Properties.ContainsKey("message"));
        Assert.True(fn.Parameters.Properties.ContainsKey("top_k"));
        Assert.False(fn.Parameters.Properties.ContainsKey("session_only"));
        Assert.False(fn.Parameters.Properties.ContainsKey("index_name"));
        Assert.False(fn.Parameters.Properties.ContainsKey("vector_search_mode"));
    }

    [Fact]
    public void ExpertTools_BuildMemoryExpertFunction_HasExpectedShape()
    {
        var fn = ExpertTools.BuildMemoryExpertFunction();

        Assert.Equal("call_memory_expert", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.Contains("message", fn.Parameters.Required);
        Assert.True(fn.Parameters.Properties.ContainsKey("message"));
        Assert.False(fn.Parameters.Properties.ContainsKey("user_id"));
        Assert.False(fn.Parameters.Properties.ContainsKey("session_id"));
    }

    [Fact]
    public void MemoryQueryTools_BuildMemoryTurnRangeFunction_ExposesPagedRangeParameters()
    {
        var fn = MemoryQueryTools.BuildMemoryTurnRangeFunction();

        Assert.Equal("get_memory_turn_range", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.Contains("session_id", fn.Parameters.Required);
        Assert.Contains("start_turn_index", fn.Parameters.Required);
        Assert.Contains("end_turn_index", fn.Parameters.Required);
        Assert.True(fn.Parameters.Properties.ContainsKey("offset"));
        Assert.Contains("20", fn.Description);
    }

    [Fact]
    public void MonitorBuilders_IncludeMemoryExpertFunction()
    {
        var monitor = new MonitorToolsBuilder();
        var hal = new Hal9000MonitorToolsBuilder();

        var monitorFns = monitor.Tools.Select(t => t.Function?.Name).Where(n => !string.IsNullOrWhiteSpace(n)).ToList();
        var halFns = hal.Tools.Select(t => t.Function?.Name).Where(n => !string.IsNullOrWhiteSpace(n)).ToList();

        Assert.Contains("call_memory_expert", monitorFns);
        Assert.Contains("call_memory_expert", halFns);
    }

    [Fact]
    public void ToolsBuilderFactory_CreatesMemoryBuilder()
    {
        var logger = Mock.Of<ILogger<ToolsBuilderFactory>>();
        var registry = new Mock<IFunctionDefinitionRegistry>();
        var mlParams = new MLParams
        {
            ExpertExtraPrompt = string.Empty,
            SimpleMonitorPromptByRunner = new Dictionary<string, bool>(),
            PrimaryMonitorRoleByRunner = new Dictionary<string, string>()
        };
        var systemParams = new SystemParams
        {
            UserFacingServiceId = "monitor"
        };

        var factory = new ToolsBuilderFactory(logger, registry.Object, mlParams, systemParams);
        var builder = factory.Create("memory");

        Assert.IsType<MemoryExpertToolsBuilder>(builder);
        Assert.True(factory.AvailableIds().Any(id => id.Equals("memory", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains("execute_query_memory", builder.Tools.Select(t => t.Function?.Name));
        Assert.Contains("get_memory_turn_range", builder.Tools.Select(t => t.Function?.Name));
    }
}

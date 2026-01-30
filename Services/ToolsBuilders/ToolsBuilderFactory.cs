using System;
using System.Collections.Generic;
using System.Collections.Concurrent; // GetOrAdd
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects;

namespace NetworkMonitor.LLM.Services;

public interface IToolsBuilderFactory
{
    /// <summary>Create a tools builder by its identifier.</summary>
    /// <param name="toolsId">The tools identifier (e.g. "nmap", "json_dynamic").</param>
    /// <param name="jsonSpec">When using "json_dynamic", the serialized <see cref="ToolBuilderSpec"/>.</param>
    IToolsBuilder Create(string toolsId, string? jsonSpec = null, bool enableAgentFlow = false, string? runnerType = null);

    /// <summary>All statically-registered tools IDs.</summary>
    IEnumerable<string> AvailableIds();
}

public sealed class ToolsBuilderFactory : IToolsBuilderFactory
{
    private const string JSON_DYNAMIC_ID = "json_dynamic";

    private readonly ILogger _logger;
    private readonly IFunctionDefinitionRegistry _functionDefinitionRegistry;
    private readonly MLParams _mlParams;
    private readonly SystemParams _systemParams;

    // No userInfo anymore — parameterless ctor factory
    private readonly Dictionary<string, Func<IToolsBuilder>> _static;

    // Cache for json_dynamic builders (keyed by spec.Id)
    private readonly ConcurrentDictionary<string, IToolsBuilder> _dynamicCache =
        new(StringComparer.OrdinalIgnoreCase);

    public ToolsBuilderFactory(
        ILogger<ToolsBuilderFactory> logger,
        IFunctionDefinitionRegistry functionDefinitionRegistry,
        MLParams mlParams,
        SystemParams systemParams)
    {
        _logger = logger;
        _functionDefinitionRegistry = functionDefinitionRegistry;
        _mlParams = mlParams;
        _systemParams = systemParams;

        _static = new(StringComparer.OrdinalIgnoreCase)
        {
            { "timesfm",       () => new BlankToolsBuilder() },
            { "blogmonitor", () => new BlogMonitorToolsBuilder() },
            { "reportdata",  () => new ReportDataToolsBuilder() },
            { "monitorsys",  () => new MonitorToolsBuilder() },
            { "user",        () => new UserToolsBuilder() },
            { "cmdprocessor",() => new CmdProcessorExpertToolsBuilder() },
            { "connect",     () => new ConnectExpertToolsBuilder() },
            { "nmap",        () => new SecurityExpertToolsBuilder() },
            { "meta",        () => new PenetrationExpertToolsBuilder() },
            { "search",      () => new SearchExpertToolsBuilder() },
            { "quantum",     () => new QuantumExpertToolsBuilder() },
            { "agentflow",   () => new AgentFlowExpertToolsBuilder(_functionDefinitionRegistry) },

        };
    }

    // MAIN ENTRY POINT ----------------------------------------------------
    public IToolsBuilder Create(string toolsId, string? jsonSpec = null, bool enableAgentFlow = false, string? runnerType = null)
    {
        // 1️⃣  Dynamic JSON path
        if (toolsId.Equals(JSON_DYNAMIC_ID, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(jsonSpec))
                throw new ArgumentException("JsonToolsBuilderSpec must be supplied when toolsId = 'json_dynamic'");

            var spec = JsonSerializer.Deserialize<ToolBuilderSpec>(jsonSpec!)
                      ?? throw new ArgumentException("Invalid JsonToolsBuilderSpec payload.");

            _logger.LogInformation("Success: got json spec for Tools Builder: {SpecId}", spec.Id);

            return _dynamicCache.GetOrAdd(
                spec.Id,
                _ => new JsonDrivenToolsBuilder(spec, _functionDefinitionRegistry));
        }

        if (ShouldUseSimpleMonitorPrompt(toolsId, runnerType))
        {
            return new MonitorSimpleToolsBuilder();
        }

        // 2️⃣  Static path
        if (_static.TryGetValue(toolsId, out var ctor))
        {
            return ctor();
        }

        // Fallback
        return new MonitorToolsBuilder(enableAgentFlow);
    }

    public IEnumerable<string> AvailableIds() => _static.Keys;

    private bool ShouldUseSimpleMonitorPrompt(string toolsId, string? runnerType)
    {
        if (string.IsNullOrWhiteSpace(runnerType))
        {
            return false;
        }

        if (!IsMonitorToolsId(toolsId))
        {
            return false;
        }

        if (!IsMonitorUserFacingService())
        {
            return false;
        }

        return _mlParams.SimpleMonitorPromptByRunner.TryGetValue(runnerType, out var useSimple) && useSimple;
    }

    private static bool IsMonitorToolsId(string toolsId)
    {
        return toolsId.Equals("monitor", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsMonitorUserFacingService()
    {
        return _systemParams.UserFacingServiceId?.Equals("monitor", StringComparison.OrdinalIgnoreCase) == true;
    }
}

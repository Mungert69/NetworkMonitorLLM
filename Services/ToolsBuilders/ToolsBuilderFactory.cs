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
        ExpertPromptComposer.SetExtraPrompt(_mlParams.ExpertExtraPrompt);
        ExpertPromptComposer.SetCameraReferenceIdentity(
            _mlParams.CameraReferenceIdentityName,
            _mlParams.CameraReferenceIdentityImageUrl,
            _mlParams.CameraReferenceIdentityInstructions,
            _mlParams.LlmUseInlineImageData,
            _mlParams.LlmUseCacheHttpImageUrls);

        _static = new(StringComparer.OrdinalIgnoreCase)
        {
            { "timesfm",       () => new BlankToolsBuilder() },
            { "blogmonitor", () => new BlogMonitorToolsBuilder() },
            { "reportdata",  () => new ReportDataToolsBuilder() },
            { "monitorsys",  () => new MonitorSysToolsBuilder() },
            { "user",        () => new UserToolsBuilder() },
            { "cmdprocessor",() => new CmdProcessorExpertToolsBuilder() },
            { "connect",     () => new ConnectExpertToolsBuilder() },
            { "nmap",        () => new SecurityExpertToolsBuilder() },
            { "meta",        () => new PenetrationExpertToolsBuilder() },
            { "metalive",    () => new LivePenetrationExpertToolsBuilder() },
            { "search",      () => new SearchExpertToolsBuilder() },
            { "memory",      () => new MemoryExpertToolsBuilder() },
            { "quantum",     () => new QuantumExpertToolsBuilder() },
            { "camera",      () => new CameraExpertToolsBuilder() },
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

        if (TryCreatePrimaryMonitorBuilder(toolsId, runnerType, enableAgentFlow, out var monitorBuilder))
        {
            return monitorBuilder;
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

    private bool TryCreatePrimaryMonitorBuilder(string toolsId, string? runnerType, bool enableAgentFlow, out IToolsBuilder builder)
    {
        builder = null!;
        if (!IsMonitorToolsId(toolsId) || !IsMonitorUserFacingService())
        {
            return false;
        }

        var role = ResolvePrimaryMonitorRole(runnerType);
        if (string.IsNullOrWhiteSpace(role))
        {
            return false;
        }

        switch (role.Trim().ToLowerInvariant())
        {
            case "standard":
                builder = new MonitorToolsBuilder(enableAgentFlow);
                return true;
            case "simple":
                builder = new MonitorSimpleToolsBuilder();
                return true;
            case "hal9000":
            case "hal":
                builder = new Hal9000MonitorToolsBuilder(enableAgentFlow);
                return true;
            case "hal9000_simple":
            case "hal_simple":
                builder = new Hal9000MonitorSimpleToolsBuilder();
                return true;
            default:
                _logger.LogWarning(
                    "Unknown PrimaryMonitorRole '{Role}'. Falling back to legacy monitor prompt selection.",
                    role);
                return false;
        }
    }

    private string ResolvePrimaryMonitorRole(string? runnerType)
    {
        if (!string.IsNullOrWhiteSpace(runnerType) &&
            _mlParams.PrimaryMonitorRoleByRunner.TryGetValue(runnerType, out var byRunnerRole) &&
            !string.IsNullOrWhiteSpace(byRunnerRole))
        {
            return byRunnerRole;
        }

        return _mlParams.PrimaryMonitorRole;
    }
}

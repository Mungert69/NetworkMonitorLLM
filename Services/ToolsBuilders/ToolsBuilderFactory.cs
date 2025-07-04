using System;                                  
using NetworkMonitor.Objects;
using System.Collections.Concurrent;              // ← NEW
using System.Text.Json;   
using System.Collections.Generic;
using System.Collections.Concurrent;    // GetOrAdd
using System.Text.Json;
using Microsoft.Extensions.Logging;    
namespace NetworkMonitor.LLM.Services;
 public interface IToolsBuilderFactory
    {
        /// <summary>
        /// Create a tools builder by its identifier.
        /// </summary>
        /// <param name="toolsId">The tools identifier (e.g. "nmap", "json_dynamic").</param>
        /// <param name="userInfo">Optional user context.</param>
        /// <param name="jsonSpec">When using "json_dynamic", the serialized <see cref="ToolBuilderSpec"/>.</param>
        IToolsBuilder Create(string toolsId, UserInfo? userInfo = null, string? jsonSpec = null);

        /// <summary>
        /// All statically-registered tools IDs.
        /// </summary>
        IEnumerable<string> AvailableIds();
    }

public sealed class ToolsBuilderFactory : IToolsBuilderFactory
{
    private const string JSON_DYNAMIC_ID = "json_dynamic";
      private readonly ILogger _logger;

    private readonly Dictionary<string, Func<UserInfo?, IToolsBuilder>> _static;
    IFunctionDefinitionRegistry _functionDefinitionRegistry;
    private readonly ConcurrentDictionary<string, IToolsBuilder> _dynamicCache = new(StringComparer.OrdinalIgnoreCase);

    public ToolsBuilderFactory( ILogger<ToolsBuilderFactory> logger,IFunctionDefinitionRegistry functionDefinitionRegistry)
    {
        _functionDefinitionRegistry = functionDefinitionRegistry;
        _logger = logger;
        _static = new(StringComparer.OrdinalIgnoreCase)
        {
             { "blogmonitor", user => new BlogMonitorToolsBuilder(user) },
            { "reportdata",  _    => new ReportDataToolsBuilder() },
            { "monitorsys",  user => new MonitorToolsBuilder(user) },
            { "user",        user => new UserToolsBuilder(user) },
            { "cmdprocessor",user => new CmdProcessorExpertToolsBuilder(user) },
            { "nmap",        _    => new SecurityExpertToolsBuilder() },
            { "meta",        _    => new PenetrationExpertToolsBuilder() },
            { "search",      _    => new SearchExpertToolsBuilder() },
            { "quantum",     _    => new QuantumExpertToolsBuilder() },
            { "security_agent_collector",    _ => new SecurityAgentNodeToolsBuilder() },
            { "security_agent_interpretor",_ => new SecurityInterpretNodeToolsBuilder() }
        };
    }

    // MAIN ENTRY POINT ----------------------------------------------------
    public IToolsBuilder Create(string toolsId,
                                UserInfo? userInfo = null,
                                string?  jsonSpec  = null)
    {
        // 1️⃣  Dynamic JSON path
        if (toolsId.Equals(JSON_DYNAMIC_ID, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(jsonSpec))
                throw new ArgumentException(
                    "JsonToolsBuilderSpec must be supplied when toolsId = 'json_dynamic'");

            // cache by the *spec.Id* so the same builder is reused
            var spec = JsonSerializer.Deserialize<ToolBuilderSpec>(jsonSpec)!;
            _logger.LogInformation($"Success : got json spec for Tools Builder : {spec}");
            return _dynamicCache.GetOrAdd(spec.Id,
                _ => new JsonDrivenToolsBuilder(spec, _functionDefinitionRegistry));
        }

        // 2️⃣  Static path (existing behaviour)
        if (_static.TryGetValue(toolsId, out var ctor))
            return ctor(userInfo);

        return new MonitorToolsBuilder(userInfo); // fallback
    }

    public IEnumerable<string> AvailableIds() => _static.Keys;
}


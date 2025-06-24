using System;                            
using System.Collections.Generic;        
using NetworkMonitor.Objects;


namespace NetworkMonitor.LLM.Services;
public sealed class ToolsBuilderFactory
{

    // Map the string key you’ll pass in the request
    // to a *builder-creating* lambda
    private readonly Dictionary<string,
        Func<UserInfo?, IToolsBuilder>> _map;

    public ToolsBuilderFactory()
    {

        _map = new(StringComparer.OrdinalIgnoreCase)
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
            { "security_agent_interpretor",_ => new SecurityInterpretNodeToolsBuilder() },
        };
    }

    // -------------- PUBLIC API --------------

    /// <summary>
    /// Returns an IToolsBuilder; falls back to MonitorToolsBuilder
    /// if the id is unknown.
    /// </summary>
    public IToolsBuilder Create(string toolsDefinitionId,
                                UserInfo? userInfo = null)
    {
        if (_map.TryGetValue(toolsDefinitionId, out var ctor))
            return ctor(userInfo);

        // default / safe-fallback
        return new MonitorToolsBuilder(userInfo);
    }

    public IEnumerable<string> AvailableIds() => _map.Keys;
}

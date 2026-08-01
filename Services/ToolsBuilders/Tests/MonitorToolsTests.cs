using System.Collections.Generic;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class MonitorToolsTests
{
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

using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.Factory;
using Xunit;

namespace NetworkMonitor.LLM.Services.Tests;

public class MonitorEndpointDiscoveryTests
{
    [Fact]
    public void MonitorBuildersExposeOptionalDiscovery()
    {
        foreach (var builder in new ToolsBuilderBase[] { new MonitorToolsBuilder(), new MonitorSimpleToolsBuilder(), new MonitorSysToolsBuilder() })
            Assert.Contains(builder.Tools, tool => tool.Function?.Name == "get_available_endpoints");
    }

    [Theory]
    [InlineData("Free")]
    [InlineData("Standard")]
    [InlineData("Professional")]
    [InlineData("Enterprise")]
    [InlineData("God")]
    public void DiscoveryHasSamePlanAccessAsAgentListing(string plan)
    {
        var functions = AccountTypeFactory.GetFunctionNamesForAccountType(plan);
        Assert.Contains("get_agents", functions);
        Assert.Contains("get_available_endpoints", functions);
    }

    [Fact]
    public void AddAndEditAcceptCustomEndpointsWithoutBuiltInEnum()
    {
        foreach (var function in new[] { MonitorTools.BuildAddHostFunction(), MonitorTools.BuildEditHostFunction() })
        {
            var property = function.Parameters!.Properties!["endpoint"];
            Assert.Equal("string", property.Type);
            Assert.True(property.Enum == null || property.Enum.Count == 0);
            Assert.Contains("helloworld", property.Description);
            Assert.Contains("never retry", property.Description);
        }
    }

    [Fact]
    public void DiscoveryDoesNotRequireAnAgentOrMakeDiscoveryMandatory()
    {
        var function = MonitorTools.BuildGetAvailableEndpointsFunction();
        Assert.Equal("get_available_endpoints", function.Name);
        Assert.True(function.Parameters!.Required == null || function.Parameters.Required.Count == 0);
        Assert.Contains("not required", function.Description);
        Assert.Contains("public/system", function.Description);
        Assert.Equal("string", function.Parameters.Properties!["agent_location"].Type);
    }
}

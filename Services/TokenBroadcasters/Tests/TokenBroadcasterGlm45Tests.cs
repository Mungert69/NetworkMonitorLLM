using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterGlm45Tests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterGlm_4_5 CreateBroadcaster(bool xmlFunctionParsing = false)
        => new TokenBroadcasterGlm_4_5(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: xmlFunctionParsing,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_ParsesToolCallWithArgPairs()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<tool_call>get_agents<arg_key>detail_response</arg_key><arg_value>false</arg_value></tool_call>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_agents", result[0].functionName);
        using var doc = JsonDocument.Parse(result[0].json);
        Assert.False(doc.RootElement.GetProperty("detail_response").GetBoolean());
    }

    [Fact]
    public void ParseInputForJson_ParsesMultipleArgPairsWithTypes()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<tool_call>run_nmap<arg_key>target</arg_key><arg_value>192.168.1.1</arg_value><arg_key>number_lines</arg_key><arg_value>50</arg_value></tool_call>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("run_nmap", result[0].functionName);
        using var doc = JsonDocument.Parse(result[0].json);
        Assert.Equal("192.168.1.1", doc.RootElement.GetProperty("target").GetString());
        Assert.Equal(50, doc.RootElement.GetProperty("number_lines").GetInt32());
    }

    [Fact]
    public void ParseInputForJson_ParsesJsonEnvelopeCompatibility()
    {
        var broadcaster = CreateBroadcaster();
        var input = "<tool_call>{\"name\":\"get_user_info\",\"arguments\":{\"detail_response\":true}}</tool_call>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_user_info", result[0].functionName);
        using var doc = JsonDocument.Parse(result[0].json);
        Assert.True(doc.RootElement.GetProperty("detail_response").GetBoolean());
    }
}

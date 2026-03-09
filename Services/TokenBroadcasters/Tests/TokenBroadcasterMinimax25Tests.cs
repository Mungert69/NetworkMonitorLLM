using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterMinimax25Tests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterMinimax_2_5 CreateBroadcaster(bool xmlFunctionParsing = false)
        => new TokenBroadcasterMinimax_2_5(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: xmlFunctionParsing,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_ParsesSingleInvokeWithParameters()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<minimax:tool_call><invoke name=\"run_nmap\"><parameter name=\"target\">192.168.1.1</parameter><parameter name=\"scan_options\">-sS -T4</parameter></invoke></minimax:tool_call>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("run_nmap", result[0].functionName);
        using var doc = JsonDocument.Parse(result[0].json);
        Assert.Equal("192.168.1.1", doc.RootElement.GetProperty("target").GetString());
        Assert.Equal("-sS -T4", doc.RootElement.GetProperty("scan_options").GetString());
    }

    [Fact]
    public void ParseInputForJson_ParsesMultipleInvokesFromSingleBlock()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<minimax:tool_call>" +
            "<invoke name=\"function_status_with_message_id\"><parameter name=\"message_id\">A1</parameter></invoke>" +
            "<invoke name=\"function_status_with_message_id\"><parameter name=\"message_id\">B2</parameter></invoke>" +
            "</minimax:tool_call>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Equal(2, result.Count);
        Assert.Equal("function_status_with_message_id", result[0].functionName);
        Assert.Equal("function_status_with_message_id", result[1].functionName);
    }

    [Fact]
    public void ParseInputForJson_ParsesJsonParameterValue()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<minimax:tool_call><invoke name=\"run_nmap\"><parameter name=\"options\">{\"ports\":[80,443],\"aggressive\":true}</parameter></invoke></minimax:tool_call>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        using var doc = JsonDocument.Parse(result[0].json);
        var options = doc.RootElement.GetProperty("options");
        Assert.True(options.GetProperty("aggressive").GetBoolean());
        Assert.Equal(2, options.GetProperty("ports").GetArrayLength());
    }
}

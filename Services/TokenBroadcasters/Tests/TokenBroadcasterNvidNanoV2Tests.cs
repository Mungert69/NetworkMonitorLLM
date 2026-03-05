using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterNvidNanoV2Tests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterNvid_Nano_V2 CreateBroadcaster(bool xmlFunctionParsing = false)
        => new TokenBroadcasterNvid_Nano_V2(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: xmlFunctionParsing,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_ParsesToolCallArray()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<TOOLCALL>[{\"name\":\"get_host_list\",\"arguments\":{\"detail_response\":true}}, {\"name\":\"cancel_functions\",\"arguments\":{\"message_id\":\"m-1\"}}]</TOOLCALL>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Equal(2, result.Count);
        Assert.Equal("get_host_list", result[0].functionName);
        Assert.Equal("cancel_functions", result[1].functionName);

        using var firstDoc = JsonDocument.Parse(result[0].json);
        using var secondDoc = JsonDocument.Parse(result[1].json);
        Assert.True(firstDoc.RootElement.GetProperty("detail_response").GetBoolean());
        Assert.Equal("m-1", secondDoc.RootElement.GetProperty("message_id").GetString());
    }

    [Fact]
    public void ParseInputForJson_ParsesStringifiedArguments()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<TOOLCALL>[{\"name\":\"get_host_list\",\"arguments\":\"{\\\"detail_response\\\":true,\\\"page_size\\\":5}\"}]</TOOLCALL>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);
        using var doc = JsonDocument.Parse(result[0].json);
        Assert.True(doc.RootElement.GetProperty("detail_response").GetBoolean());
        Assert.Equal(5, doc.RootElement.GetProperty("page_size").GetInt32());
    }

    [Fact]
    public void ParseInputForJson_RemovesThinkingAndParsesToolCall()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<think>internal reasoning</think><TOOLCALL>[{\"name\":\"get_host_list\",\"arguments\":{\"detail_response\":false}}]</TOOLCALL>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);
    }

    [Fact]
    public void ParseInputForJson_DoesNotMatchTextOnly()
    {
        var broadcaster = CreateBroadcaster();
        var input = "Regular assistant response without tool call markup.";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Empty(result);
    }
}

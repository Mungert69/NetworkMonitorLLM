using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterDeepseek32ExpTests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterDeepseek_3_2_Exp CreateBroadcaster(bool xmlFunctionParsing = false)
        => new TokenBroadcasterDeepseek_3_2_Exp(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: xmlFunctionParsing,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_ParsesToolCallBlocks()
    {
        var broadcaster = CreateBroadcaster();

        var input =
            "<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>edit_host<｜tool▁sep｜>{\"id\":23,\"endpoint\":\"icmp\"}<｜tool▁call▁end｜>" +
            "<｜tool▁call▁begin｜>edit_host<｜tool▁sep｜>{\"id\":24,\"endpoint\":\"icmp\"}<｜tool▁call▁end｜>" +
            "<｜tool▁calls▁end｜><｜end▁of▁sentence｜>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Equal(2, result.Count);
        Assert.Equal("edit_host", result[0].functionName);
        Assert.Equal("edit_host", result[1].functionName);

        using var firstDoc = JsonDocument.Parse(result[0].json);
        using var secondDoc = JsonDocument.Parse(result[1].json);
        Assert.Equal(23, firstDoc.RootElement.GetProperty("id").GetInt32());
        Assert.Equal(24, secondDoc.RootElement.GetProperty("id").GetInt32());
    }

    [Fact]
    public void ParseInputForJson_IgnoresToolOutputs()
    {
        var broadcaster = CreateBroadcaster();

        var input = "<｜tool▁output▁begin｜>{\"message\":\"ok\"}<｜tool▁output▁end｜>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Empty(result);
    }

    [Fact]
    public void ParseInputForJson_DoesNotMatchTextOnly()
    {
        var broadcaster = CreateBroadcaster();

        var input = "No tool calls here, just a response.";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Empty(result);
    }

    [Fact]
    public void ParseInputForJson_FallsBackToXmlWhenEnabled()
    {
        var broadcaster = CreateBroadcaster(xmlFunctionParsing: true);

        var input = "<function_call name=\"get_host_list\"><parameters><detail_response>true</detail_response></parameters></function_call>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);

        using var doc = JsonDocument.Parse(result[0].json);
        Assert.Equal("true", doc.RootElement.GetProperty("detail_response").GetString());
        Assert.False(doc.RootElement.GetProperty("args_escaped").GetBoolean());
    }
}

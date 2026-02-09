using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterDeepseekR1Tests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterDeepseekR1 CreateBroadcaster(bool xmlFunctionParsing = false)
        => new TokenBroadcasterDeepseekR1(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: xmlFunctionParsing,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_ParsesToolCallsWithCodeFence()
    {
        var broadcaster = CreateBroadcaster();

        var input =
            "First, updating host ID 23:\n" +
            "{\n" +
            "  \"name\": \"edit_host\",\n" +
            "  \"parameters\": {\n" +
            "    \"id\": 23,\n" +
            "    \"endpoint\": \"icmp\"\n" +
            "  }\n" +
            "}\n" +
            "<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>edit_host\n" +
            "```json\n" +
            "{\"id\":23,\"endpoint\":\"icmp\"}\n" +
            "```\n" +
            "<｜tool▁call▁end｜>\n" +
            "<｜tool▁call▁begin｜>function<｜tool▁sep｜>edit_host\n" +
            "```json\n" +
            "{\"id\":24,\"endpoint\":\"icmp\"}\n" +
            "```\n" +
            "<｜tool▁call▁end｜><｜tool▁calls▁end｜><｜end▁of▁sentence｜>";

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

        var input =
            "<｜tool▁outputs▁begin｜><｜tool▁output▁begin｜>{\"message\":\"ok\"}<｜tool▁output▁end｜><｜tool▁outputs▁end｜>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Empty(result);
    }

    [Fact]
    public void ParseInputForJson_ParsesArgumentsWithoutCodeFence()
    {
        var broadcaster = CreateBroadcaster();

        var input =
            "<｜tool▁call▁begin｜>function<｜tool▁sep｜>get_host_list\n" +
            "{\"detail_response\":true}\n" +
            "<｜tool▁call▁end｜>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);

        using var doc = JsonDocument.Parse(result[0].json);
        Assert.True(doc.RootElement.GetProperty("detail_response").GetBoolean());
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

using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterLlama32Tests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterLlama_3_2 CreateBroadcaster()
        => new TokenBroadcasterLlama_3_2(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: false,
            ignoreParameters: _ignoreParameters);

    private static JsonElement ParseJson(string json)
        => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void ParseInputForJson_ParsesPrettyPrintedJsonWithTabsAndNewlines()
    {
        var broadcaster = CreateBroadcaster();

        var input = "Here you go:\n\n{\n\t\"name\": \"get_host_list\",\n\t\"parameters\": {\n\t\t\"detail_response\": true,\n\t\t\"page_number\": 1,\n\t\t\"page_size\": 10\n\t}\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);

        var parameters = ParseJson(result[0].json);
        Assert.True(parameters.GetProperty("detail_response").GetBoolean());
        Assert.Equal(1, parameters.GetProperty("page_number").GetInt32());
        Assert.Equal(10, parameters.GetProperty("page_size").GetInt32());
    }

    [Fact]
    public void ParseInputForJson_ParsesMultipleFunctionCalls()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"name\": \"get_host_list\",\n  \"parameters\": { \"detail_response\": true }\n}\n" +
                    "{\n  \"name\": \"cancel_functions\",\n  \"parameters\": { \"message_id\": \"m-123\" }\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Equal(2, result.Count);
        Assert.Equal("get_host_list", result[0].functionName);
        Assert.Equal("cancel_functions", result[1].functionName);
    }

    [Fact]
    public void ParseInputForJson_DoesNotMatchTextOnly()
    {
        var broadcaster = CreateBroadcaster();

        var input = "This is a normal response with no function call.";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Empty(result);
    }

    [Fact]
    public void ParseInputForJson_ParsesTypeFunctionEnvelope()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"type\": \"function\",\n  \"name\": \"get_host_list\",\n  \"parameters\": { \"detail_response\": false }\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);
        var parameters = ParseJson(result[0].json);
        Assert.False(parameters.GetProperty("detail_response").GetBoolean());
    }

    [Fact]
    public void ParseInputForJson_ParsesArgumentsAlias()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"name\": \"get_host_list\",\n  \"arguments\": { \"detail_response\": true }\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);
        var parameters = ParseJson(result[0].json);
        Assert.True(parameters.GetProperty("detail_response").GetBoolean());
    }

    [Fact]
    public void ParseInputForJson_ParsesNestedFunctionObject()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"function\": { \"name\": \"get_host_list\", \"arguments\": { \"detail_response\": true } }\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);
        var parameters = ParseJson(result[0].json);
        Assert.True(parameters.GetProperty("detail_response").GetBoolean());
    }

    [Fact]
    public void ParseInputForJson_ParsesParametersProvidedAsStringJson()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"name\": \"get_host_list\",\n  \"parameters\": \"{\\\"detail_response\\\": true, \\\"page_size\\\": 10}\"\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);
        var parameters = ParseJson(result[0].json);
        Assert.True(parameters.GetProperty("detail_response").GetBoolean());
        Assert.Equal(10, parameters.GetProperty("page_size").GetInt32());
    }

    [Fact]
    public void ParseInputForJson_IgnoresObjectsWithoutParameters()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"name\": \"get_host_list\"\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Empty(result);
    }

    [Fact]
    public void ParseInputForJson_IgnoresObjectsWithoutName()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"parameters\": { \"detail_response\": true }\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Empty(result);
    }

    [Fact]
    public void ParseInputForJson_SkipsInvalidThenParsesValid()
    {
        var broadcaster = CreateBroadcaster();

        var input = "{\n  \"name\": \"broken\",\n  \"parameters\": { \"detail_response\": true \n}\n" +
                    "{\n  \"name\": \"get_host_list\",\n  \"parameters\": { \"detail_response\": true }\n}\n";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("get_host_list", result[0].functionName);
    }
}

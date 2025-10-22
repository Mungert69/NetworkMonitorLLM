using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterGptOssTests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterGptOss CreateBroadcaster()
        => new TokenBroadcasterGptOss(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: false,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_NormalizesFunctionNameToSnakeCase()
    {
        var broadcaster = CreateBroadcaster();

        var input =
            "User wants to list their hosts. We'll call function.commentary to=functions.getHostList " +
            "<|constrain|>json<|message|>{\"detail_response\": false}";

        var result = broadcaster.ParseInputForJson(input);

        Assert.NotEmpty(result);
        Assert.Equal("get_host_list", result[0].functionName);
    }

    [Fact]
    public void ParseInputForJson_UsesPayloadFromMessageBlock()
    {
        var broadcaster = CreateBroadcaster();

        var jsonPayload = "{\"detail_response\": true, \"page_size\": 10}";
        var input = $"function.commentary to=functions.sampleFunc <|constrain|>json<|message|>{jsonPayload}";

        var result = broadcaster.ParseInputForJson(input);

        Assert.NotEmpty(result);
        Assert.Equal("sample_func", result[0].functionName);
        Assert.Equal(jsonPayload, result[0].json);
    }

    [Fact]
    public void ParseInputForJson_ExtractsNameFromPayloadWhenDestinationMissing()
    {
        var broadcaster = CreateBroadcaster();

        var input =
            "Assistant commentary <|constrain|>json<|message|>{" +
            "\"name\": \"cancelFunctions\", \"arguments\": {\"message_id\": \"abc123\"}}";

        var result = broadcaster.ParseInputForJson(input);

        Assert.NotEmpty(result);
        Assert.Equal("cancel_functions", result[0].functionName);
        Assert.Equal("{\"message_id\":\"abc123\"}", result[0].json);
    }

}

using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterMellum2Tests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterMellum2 CreateBroadcaster(bool xmlFunctionParsing = false)
        => new TokenBroadcasterMellum2(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: xmlFunctionParsing,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_ParsesSingleToolCallWithParameters()
    {
        var broadcaster = CreateBroadcaster();
        var input = "<tool_call><function=run_nmap><parameter=target>192.168.1.1</parameter><parameter=scan_options>-sS -T4</parameter></function>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("run_nmap", result[0].functionName);
        using var doc = JsonDocument.Parse(result[0].json);
        Assert.Equal("192.168.1.1", doc.RootElement.GetProperty("target").GetString());
        Assert.Equal("-sS -T4", doc.RootElement.GetProperty("scan_options").GetString());
    }

    [Fact]
    public void ParseInputForJson_ParsesMultipleToolCalls()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<tool_call><function=run_nmap><parameter=target>10.0.0.1</parameter></function>" +
            "<tool_call><function=run_nmap><parameter=target>10.0.0.2</parameter></function>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Equal(2, result.Count);
        Assert.Equal("run_nmap", result[0].functionName);
        Assert.Equal("run_nmap", result[1].functionName);
        using var doc0 = JsonDocument.Parse(result[0].json);
        using var doc1 = JsonDocument.Parse(result[1].json);
        Assert.Equal("10.0.0.1", doc0.RootElement.GetProperty("target").GetString());
        Assert.Equal("10.0.0.2", doc1.RootElement.GetProperty("target").GetString());
    }

    [Fact]
    public void ParseInputForJson_ParsesJsonParameterValue()
    {
        var broadcaster = CreateBroadcaster();
        var input = "<tool_call><function=run_nmap><parameter=options>{\"ports\":[80,443],\"aggressive\":true}</parameter></function>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        using var doc = JsonDocument.Parse(result[0].json);
        var options = doc.RootElement.GetProperty("options");
        Assert.True(options.GetProperty("aggressive").GetBoolean());
        Assert.Equal(2, options.GetProperty("ports").GetArrayLength());
    }

    [Fact]
    public void ParseInputForJson_ParsesRawJsonBodyWhenNoParameterTags()
    {
        var broadcaster = CreateBroadcaster();
        var input = "<tool_call><function=run_nmap>{\"target\":\"192.168.1.186\",\"scan_options\":\"-sS -T4\"}</function>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("run_nmap", result[0].functionName);
        using var doc = JsonDocument.Parse(result[0].json);
        Assert.Equal("192.168.1.186", doc.RootElement.GetProperty("target").GetString());
        Assert.Equal("-sS -T4", doc.RootElement.GetProperty("scan_options").GetString());
    }
}

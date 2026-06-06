using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.LLM.Services;
using Xunit;

namespace NetworkMonitorLLM.Tests.TokenBroadcasters;

public class TokenBroadcasterMiniCPM5Tests
{
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly HashSet<string> _ignoreParameters = new();

    private TokenBroadcasterMiniCPM_5 CreateBroadcaster(bool xmlFunctionParsing = false)
        => new TokenBroadcasterMiniCPM_5(
            _responseProcessor.Object,
            _logger.Object,
            xmlFunctionParsing: xmlFunctionParsing,
            ignoreParameters: _ignoreParameters);

    [Fact]
    public void ParseInputForJson_ParsesDirectFunctionBlocks()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<function name=\"run_nmap\"><param name=\"target\">192.168.1.1</param><param name=\"scan_options\">-sS -T4</param></function>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        Assert.Equal("run_nmap", result[0].functionName);

        using var doc = JsonDocument.Parse(result[0].json);
        Assert.Equal("192.168.1.1", doc.RootElement.GetProperty("target").GetString());
        Assert.Equal("-sS -T4", doc.RootElement.GetProperty("scan_options").GetString());
    }

    [Fact]
    public void ParseInputForJson_ParsesMultipleFunctionBlocks()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<function name=\"function_status_with_message_id\"><param name=\"message_id\">Y7_BzX1O13Xi</param><param name=\"auto_check_interval_seconds\">0</param></function>" +
            "<function name=\"function_status_with_message_id\"><param name=\"message_id\">TRYsCU2Xre35</param><param name=\"auto_check_interval_seconds\">0</param></function>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Equal(2, result.Count);
        Assert.Equal("function_status_with_message_id", result[0].functionName);
        Assert.Equal("function_status_with_message_id", result[1].functionName);
    }

    [Fact]
    public void ParseInputForJson_ParsesCDataParameterValues()
    {
        var broadcaster = CreateBroadcaster();
        var input =
            "<function name=\"run_nmap\"><param name=\"options\"><![CDATA[{\"ports\":[80,443],\"aggressive\":true}]]></param></function>";

        var result = broadcaster.ParseInputForJson(input);

        Assert.Single(result);
        using var doc = JsonDocument.Parse(result[0].json);
        var options = doc.RootElement.GetProperty("options");
        Assert.True(options.GetProperty("aggressive").GetBoolean());
        Assert.Equal(2, options.GetProperty("ports").GetArrayLength());
    }
}

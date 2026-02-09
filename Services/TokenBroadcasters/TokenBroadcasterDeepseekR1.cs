using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class TokenBroadcasterDeepseekR1 : TokenBroadcasterBase
{
    private const string ToolCallBegin = "<｜tool▁call▁begin｜>";
    private const string ToolCallEnd = "<｜tool▁call▁end｜>";
    private const string ToolSep = "<｜tool▁sep｜>";
    private const string JsonFence = "```json";
    private const string Fence = "```";

    public TokenBroadcasterDeepseekR1(
        ILLMResponseProcessor responseProcessor,
        ILogger logger,
        bool xmlFunctionParsing,
        HashSet<string> ignoreParameters)
        : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
    {
    }

    public override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        var functionCalls = new List<(string json, string functionName)>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return functionCalls;
        }

        input = RemoveThinking(input);

        var index = 0;
        while (true)
        {
            var callStart = input.IndexOf(ToolCallBegin, index, StringComparison.Ordinal);
            if (callStart < 0)
            {
                break;
            }

            callStart += ToolCallBegin.Length;
            var callEnd = input.IndexOf(ToolCallEnd, callStart, StringComparison.Ordinal);
            if (callEnd < 0)
            {
                break;
            }

            var callBody = input.Substring(callStart, callEnd - callStart).Trim();
            index = callEnd + ToolCallEnd.Length;

            if (!TryParseToolCall(callBody, out var functionName, out var argsJson))
            {
                continue;
            }

            var sanitizedJson = JsonSanitizer.RepairJson(argsJson, _ignoreParameters) ?? "";
            functionCalls.Add((sanitizedJson, functionName));
        }

        if (functionCalls.Count == 0 && _xmlFunctionParsing)
        {
            return base.ParseInputForXml(input);
        }

        return functionCalls;
    }

    private static bool TryParseToolCall(string callBody, out string functionName, out string argsJson)
    {
        functionName = "";
        argsJson = "";

        if (string.IsNullOrWhiteSpace(callBody))
        {
            return false;
        }

        var sepIndex = callBody.IndexOf(ToolSep, StringComparison.Ordinal);
        if (sepIndex < 0)
        {
            return false;
        }

        var afterSep = callBody.Substring(sepIndex + ToolSep.Length);
        var nameEnd = afterSep.IndexOf('\n');
        string remainder;
        if (nameEnd < 0)
        {
            functionName = afterSep.Trim();
            remainder = string.Empty;
        }
        else
        {
            functionName = afterSep.Substring(0, nameEnd).Trim();
            remainder = afterSep.Substring(nameEnd + 1);
        }

        if (string.IsNullOrWhiteSpace(functionName))
        {
            return false;
        }

        argsJson = ExtractArgumentsJson(remainder);
        if (string.IsNullOrWhiteSpace(argsJson))
        {
            return false;
        }

        return true;
    }

    private static string ExtractArgumentsJson(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "";
        }

        var jsonFenceIndex = text.IndexOf(JsonFence, StringComparison.OrdinalIgnoreCase);
        if (jsonFenceIndex >= 0)
        {
            var start = jsonFenceIndex + JsonFence.Length;
            var end = text.IndexOf(Fence, start, StringComparison.Ordinal);
            if (end > start)
            {
                return text.Substring(start, end - start).Trim();
            }
        }

        var fenceIndex = text.IndexOf(Fence, StringComparison.Ordinal);
        if (fenceIndex >= 0)
        {
            var start = fenceIndex + Fence.Length;
            var end = text.IndexOf(Fence, start, StringComparison.Ordinal);
            if (end > start)
            {
                return text.Substring(start, end - start).Trim();
            }
        }

        var firstBrace = text.IndexOf('{');
        var lastBrace = text.LastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace)
        {
            return text.Substring(firstBrace, lastBrace - firstBrace + 1).Trim();
        }

        return text.Trim();
    }
}

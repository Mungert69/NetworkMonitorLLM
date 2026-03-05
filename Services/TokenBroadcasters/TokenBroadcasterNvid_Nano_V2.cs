using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class TokenBroadcasterNvid_Nano_V2 : TokenBroadcasterBase
{
    private static readonly Regex ToolCallRegex = new(
        @"<TOOLCALL>\s*(?<payload>.*?)\s*</TOOLCALL>",
        RegexOptions.Singleline | RegexOptions.Compiled);

    public TokenBroadcasterNvid_Nano_V2(
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

        foreach (Match match in ToolCallRegex.Matches(input))
        {
            var payload = match.Groups["payload"].Value.Trim();
            if (string.IsNullOrWhiteSpace(payload))
            {
                continue;
            }

            if (!TryParseToolCallPayload(payload, out var parsedCalls))
            {
                continue;
            }

            functionCalls.AddRange(parsedCalls);
        }

        if (functionCalls.Count == 0 && _xmlFunctionParsing)
        {
            return ParseInputForXml(input);
        }

        return functionCalls;
    }

    private bool TryParseToolCallPayload(string payload, out List<(string json, string functionName)> functionCalls)
    {
        functionCalls = new List<(string json, string functionName)>();
        try
        {
            var sanitized = JsonSanitizer.SanitizeJson(payload);
            using var doc = JsonDocument.Parse(sanitized);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in root.EnumerateArray())
                {
                    if (TryParseCall(item, out var call))
                    {
                        functionCalls.Add(call);
                    }
                }
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                if (TryParseCall(root, out var call))
                {
                    functionCalls.Add(call);
                }
            }
        }
        catch (JsonException ex)
        {
            _logger.LogDebug(ex, "Failed to parse TOOLCALL payload for nvid_nano_v2.");
            return false;
        }

        return functionCalls.Count > 0;
    }

    private bool TryParseCall(JsonElement element, out (string json, string functionName) call)
    {
        call = default;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (!element.TryGetProperty("name", out var nameProp) || nameProp.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        string functionName = nameProp.GetString() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(functionName))
        {
            return false;
        }

        string argsJson = "{}";
        if (element.TryGetProperty("arguments", out var argsProp))
        {
            argsJson = ResolveArgsJson(argsProp);
        }
        else if (element.TryGetProperty("parameters", out var parametersProp))
        {
            argsJson = ResolveArgsJson(parametersProp);
        }
        else if (element.TryGetProperty("args", out var altArgsProp))
        {
            argsJson = ResolveArgsJson(altArgsProp);
        }

        call = (JsonSanitizer.RepairJson(argsJson, _ignoreParameters), functionName);
        return true;
    }

    private static string ResolveArgsJson(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object || element.ValueKind == JsonValueKind.Array)
        {
            return element.GetRawText();
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            var value = element.GetString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value))
            {
                return "{}";
            }

            try
            {
                using var doc = JsonDocument.Parse(value);
                return doc.RootElement.GetRawText();
            }
            catch (JsonException)
            {
                return JsonSerializer.Serialize(value);
            }
        }

        return element.GetRawText();
    }
}

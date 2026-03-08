using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class TokenBroadcasterGlm_4_5 : TokenBroadcasterBase
{
    private static readonly Regex ToolCallBlockRegex = new(
        @"<tool_call>\s*(?<body>.*?)\s*</tool_call>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ArgPairRegex = new(
        @"<arg_key>\s*(?<key>.*?)\s*</arg_key>\s*<arg_value>\s*(?<value>.*?)\s*</arg_value>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public TokenBroadcasterGlm_4_5(
        ILLMResponseProcessor responseProcessor,
        ILogger logger,
        bool xmlFunctionParsing,
        HashSet<string> ignoreParameters)
        : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
    {
    }

    protected override string StripExtraFuncHeader(string input)
    {
        return input.Replace("\\\n</tool_response", "");
    }

    public override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        var functionCalls = new List<(string json, string functionName)>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return functionCalls;
        }

        input = RemoveThinking(input);

        foreach (Match blockMatch in ToolCallBlockRegex.Matches(input))
        {
            var body = blockMatch.Groups["body"].Value;
            if (string.IsNullOrWhiteSpace(body))
            {
                continue;
            }

            if (!TryParseToolCallBody(body, out var functionName, out var argsJson))
            {
                continue;
            }

            functionCalls.Add((JsonSanitizer.RepairJson(argsJson, _ignoreParameters), functionName));
        }

        if (functionCalls.Count == 0 && _xmlFunctionParsing)
        {
            return ParseInputForXml(input);
        }

        return functionCalls;
    }

    private static bool TryParseToolCallBody(string body, out string functionName, out string argsJson)
    {
        functionName = string.Empty;
        argsJson = "{}";

        var trimmedBody = body.Trim();
        if (string.IsNullOrWhiteSpace(trimmedBody))
        {
            return false;
        }

        // Compatibility fallback: <tool_call>{"name":"fn","arguments":{...}}</tool_call>
        if (TryParseJsonEnvelope(trimmedBody, out functionName, out argsJson))
        {
            return true;
        }

        var firstArgIndex = trimmedBody.IndexOf("<arg_key>", StringComparison.OrdinalIgnoreCase);
        if (firstArgIndex < 0)
        {
            functionName = trimmedBody;
            return !string.IsNullOrWhiteSpace(functionName);
        }

        functionName = trimmedBody.Substring(0, firstArgIndex).Trim();
        if (string.IsNullOrWhiteSpace(functionName))
        {
            return false;
        }

        var argsRegion = trimmedBody.Substring(firstArgIndex);
        argsJson = BuildArgumentsJsonFromArgPairs(argsRegion);
        return true;
    }

    private static string BuildArgumentsJsonFromArgPairs(string argsRegion)
    {
        var pairs = new List<(string key, string value)>();
        foreach (Match match in ArgPairRegex.Matches(argsRegion))
        {
            var key = match.Groups["key"].Value.Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var value = match.Groups["value"].Value.Trim();
            pairs.Add((key, value));
        }

        if (pairs.Count == 0)
        {
            return "{}";
        }

        var builder = new StringBuilder();
        builder.Append('{');
        for (int i = 0; i < pairs.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            builder.Append(JsonSerializer.Serialize(pairs[i].key));
            builder.Append(':');
            builder.Append(RenderJsonValue(pairs[i].value));
        }

        builder.Append('}');
        return builder.ToString();
    }

    private static string RenderJsonValue(string rawValue)
    {
        if (TryNormalizeJson(rawValue, out var normalized))
        {
            return normalized;
        }

        return JsonSerializer.Serialize(rawValue);
    }

    private static bool TryParseJsonEnvelope(string raw, out string functionName, out string argsJson)
    {
        functionName = string.Empty;
        argsJson = "{}";

        if (!TryNormalizeJson(raw, out var normalizedJson))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(normalizedJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!doc.RootElement.TryGetProperty("name", out var nameElement))
            {
                return false;
            }

            functionName = nameElement.GetString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(functionName))
            {
                return false;
            }

            if (doc.RootElement.TryGetProperty("arguments", out var argsElement))
            {
                argsJson = argsElement.ValueKind == JsonValueKind.String
                    ? argsElement.GetString() ?? "{}"
                    : argsElement.GetRawText();
                return true;
            }

            if (doc.RootElement.TryGetProperty("parameters", out var parametersElement))
            {
                argsJson = parametersElement.ValueKind == JsonValueKind.String
                    ? parametersElement.GetString() ?? "{}"
                    : parametersElement.GetRawText();
                return true;
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryNormalizeJson(string raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(raw);
            normalized = doc.RootElement.GetRawText();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

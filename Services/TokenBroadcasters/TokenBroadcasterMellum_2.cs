using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class TokenBroadcasterMellum_2 : TokenBroadcasterBase
{
    // Matches an opening <tool_call> tag and captures everything until the next closing tag of any known element (e.g., </function>)
    private static readonly Regex ToolCallSectionRegex = new(
        @"<tool_call>\s*(?<inner>.*?)(?=(<tool_call>)|</tool_call>|$)",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FunctionRegex = new(
        @"\s*<function=(?<name>[^>\r\n]+)>\s*(?<body>.*?)\s*</function>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ParameterRegex = new(
        @"<parameter=(?<name>[^>\r\n]+)>\s*(?<value>.*?)\s*</parameter>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public TokenBroadcasterMellum_2(
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
            return functionCalls;

        input = RemoveThinking(input);

        // Iterate over every <tool_call> section (handles multiple calls)
        foreach (Match section in ToolCallSectionRegex.Matches(input))
        {
            var inner = section.Groups["inner"].Value;
            if (string.IsNullOrWhiteSpace(inner))
                continue;

            var functionMatch = FunctionRegex.Match(inner);
            if (!functionMatch.Success)
                continue;

            string functionName = functionMatch.Groups["name"].Value.Trim();
            if (string.IsNullOrWhiteSpace(functionName))
                continue;

            string functionBody = functionMatch.Groups["body"].Value.Trim();
            string argsJson = BuildArgumentsJson(functionBody);
            functionCalls.Add((JsonSanitizer.RepairJson(argsJson, _ignoreParameters), functionName));
        }

        if (functionCalls.Count == 0 && _xmlFunctionParsing)
            return ParseInputForXml(input);

        return functionCalls;
    }

    private static string BuildArgumentsJson(string functionBody)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match match in ParameterRegex.Matches(functionBody))
        {
            string name = match.Groups["name"].Value.Trim();
            if (string.IsNullOrWhiteSpace(name))
                continue;

            string value = match.Groups["value"].Value.Trim();
            parameters[name] = value;
        }

        if (parameters.Count == 0)
        {
            if (TryNormalizeJson(functionBody, out var rawObjectJson))
                return rawObjectJson;
            return "{}";
        }

        var builder = new StringBuilder();
        builder.Append('{');
        bool first = true;
        foreach (var pair in parameters)
        {
            if (!first) builder.Append(',');
            first = false;
            builder.Append(JsonSerializer.Serialize(pair.Key));
            builder.Append(':');
            builder.Append(RenderJsonValue(pair.Value));
        }
        builder.Append('}');
        return builder.ToString();
    }

    private static string RenderJsonValue(string rawValue)
    {
        // Try to parse as JSON first (for objects/arrays like {"ports":[80,443],"aggressive":true})
        // If that fails, treat as a string value
        if (!string.IsNullOrWhiteSpace(rawValue))
        {
            try
            {
                using var doc = JsonDocument.Parse(rawValue);
                return doc.RootElement.GetRawText();
            }
            catch (JsonException)
            {
                // Not valid JSON, treat as string
            }
        }
        return JsonSerializer.Serialize(rawValue);
    }

    private static bool TryNormalizeJson(string raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
            return false;
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

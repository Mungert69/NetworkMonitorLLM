using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public sealed class TokenBroadcasterMiniCPM_5 : TokenBroadcasterBase
{
    private static readonly Regex FunctionBlockRegex = new(
        @"<function\s+name=""(?<name>[^""]+)"">\s*(?<body>.*?)\s*</function>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ParamRegex = new(
        @"<param\s+name=""(?<name>[^""]+)"">\s*(?<value>.*?)\s*</param>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex LegacyParameterRegex = new(
        @"<parameter=(?<name>[^>\r\n]+)>\s*(?<value>.*?)\s*</parameter>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex LegacyParameterNameRegex = new(
        @"<parameter\s+name=""(?<name>[^""]+)"">\s*(?<value>.*?)\s*</parameter>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public TokenBroadcasterMiniCPM_5(
        ILLMResponseProcessor responseProcessor,
        ILogger logger,
        bool xmlFunctionParsing,
        HashSet<string> ignoreParameters)
        : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
    {
    }

    protected override string StripExtraFuncHeader(string input)
        => input.Replace("\\\n</tool_response", "");

    public override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        var functionCalls = new List<(string json, string functionName)>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return functionCalls;
        }

        input = RemoveThinking(input);

        foreach (Match block in FunctionBlockRegex.Matches(input))
        {
            string functionName = block.Groups["name"].Value.Trim();
            if (string.IsNullOrWhiteSpace(functionName))
            {
                continue;
            }

            string functionBody = block.Groups["body"].Value.Trim();
            string argsJson = BuildArgumentsJson(functionBody);
            functionCalls.Add((JsonSanitizer.RepairJson(argsJson, _ignoreParameters), functionName));
        }

        if (functionCalls.Count == 0 && _xmlFunctionParsing)
        {
            return ParseInputForXml(input);
        }

        return functionCalls;
    }

    private static string BuildArgumentsJson(string functionBody)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!TryExtractParameters(functionBody, ParamRegex, parameters) &&
            !TryExtractParameters(functionBody, LegacyParameterNameRegex, parameters) &&
            !TryExtractParameters(functionBody, LegacyParameterRegex, parameters))
        {
            if (TryNormalizeJson(functionBody, out var rawObjectJson))
            {
                return rawObjectJson;
            }

            return "{}";
        }

        var builder = new System.Text.StringBuilder();
        builder.Append('{');

        bool first = true;
        foreach (var pair in parameters)
        {
            if (!first)
            {
                builder.Append(',');
            }

            first = false;
            builder.Append(JsonSerializer.Serialize(pair.Key));
            builder.Append(':');
            builder.Append(RenderJsonValue(pair.Value));
        }

        builder.Append('}');
        return builder.ToString();
    }

    private static bool TryExtractParameters(
        string functionBody,
        Regex regex,
        IDictionary<string, string> parameters)
    {
        bool found = false;
        foreach (Match match in regex.Matches(functionBody))
        {
            string name = match.Groups["name"].Value.Trim();
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            parameters[name] = NormalizeParameterValue(match.Groups["value"].Value);
            found = true;
        }

        return found;
    }

    private static string NormalizeParameterValue(string rawValue)
    {
        string value = rawValue.Trim();
        const string cdataStart = "<![CDATA[";
        const string cdataEnd = "]]>";

        if (value.StartsWith(cdataStart, StringComparison.Ordinal) &&
            value.EndsWith(cdataEnd, StringComparison.Ordinal) &&
            value.Length >= cdataStart.Length + cdataEnd.Length)
        {
            value = value.Substring(cdataStart.Length, value.Length - cdataStart.Length - cdataEnd.Length);
        }

        return value;
    }

    private static string RenderJsonValue(string rawValue)
    {
        if (TryNormalizeJson(rawValue, out var normalized))
        {
            return normalized;
        }

        return JsonSerializer.Serialize(rawValue);
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

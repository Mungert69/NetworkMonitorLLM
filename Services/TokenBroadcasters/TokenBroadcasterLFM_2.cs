using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;
using System.Globalization;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using System.Text.RegularExpressions;

namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    /// TokenBroadcasterLFM_2 parses LFM_2 tool call output in the format:
    /// <|tool_call_start|>[get_candidate_status(candidate_id="12345")]<|tool_call_end|>Checking the current status of candidate ID 12345.
    /// It extracts the function name and parameters from the Python-style function call, ignoring the trailing text.
    /// </summary>
    public class TokenBroadcasterLFM_2 : TokenBroadcasterBase
    {
        private static readonly Regex ToolCallRegex = new(
            @"<\|tool_call_start\|\>\[(?<payload>.*?)\]<\|tool_call_end\|\>",
            RegexOptions.Singleline | RegexOptions.Compiled);

        public TokenBroadcasterLFM_2(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing, HashSet<string> ignoreParameters)
            : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
        {
        }

        public override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var functionCalls = new List<(string json, string functionName)>();

            foreach (Match match in ToolCallRegex.Matches(input))
            {
                var payload = match.Groups["payload"].Value.Trim();
                if (string.IsNullOrEmpty(payload))
                {
                    continue;
                }

                if (TryParseJsonEnvelope(payload, out var jsonCalls))
                {
                    functionCalls.AddRange(jsonCalls);
                    continue;
                }

                if (TryParseFunctionEnvelope(payload, out var functionName, out var json))
                {
                    functionCalls.Add((JsonSanitizer.RepairJson(json, _ignoreParameters), functionName));
                    continue;
                }

                _logger.LogWarning("Unable to parse LFM tool call payload: {Payload}", payload);
            }

            return functionCalls;
        }

        private bool TryParseJsonEnvelope(string payload, out List<(string json, string functionName)> functionCalls)
        {
            functionCalls = new List<(string json, string functionName)>();

            var sanitized = JsonSanitizer.SanitizeJson(payload);
            try
            {
                using var doc = JsonDocument.Parse(sanitized);
                var root = doc.RootElement;

                if (root.ValueKind == JsonValueKind.Array)
                {
                    foreach (var element in root.EnumerateArray())
                    {
                        if (TryExtractFromJsonElement(element, out var entry))
                        {
                            functionCalls.Add(entry);
                        }
                    }
                }
                else if (root.ValueKind == JsonValueKind.Object && TryExtractFromJsonElement(root, out var singleEntry))
                {
                    functionCalls.Add(singleEntry);
                }
            }
            catch (JsonException)
            {
                return false;
            }

            return functionCalls.Count > 0;
        }

        private bool TryExtractFromJsonElement(JsonElement element, out (string json, string functionName) entry)
        {
            entry = default;
            if (element.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            string functionName = "";
            if (element.TryGetProperty("name", out var nameProp) && nameProp.ValueKind == JsonValueKind.String)
            {
                functionName = nameProp.GetString() ?? "";
            }
            else if (element.TryGetProperty("function", out var functionProp) && functionProp.ValueKind == JsonValueKind.String)
            {
                functionName = functionProp.GetString() ?? "";
            }
            else if (element.TryGetProperty("tool", out var toolProp) && toolProp.ValueKind == JsonValueKind.String)
            {
                functionName = toolProp.GetString() ?? "";
            }

            if (string.IsNullOrWhiteSpace(functionName))
            {
                return false;
            }

            var (foundArgs, argsJson) = TryExtractArguments(element);
            if (!foundArgs)
            {
                argsJson = "{}";
            }

            entry = (JsonSanitizer.RepairJson(argsJson, _ignoreParameters), functionName);
            return true;
        }

        private (bool Found, string Json) TryExtractArguments(JsonElement element)
        {
            if (element.TryGetProperty("parameters", out var parametersProp))
            {
                return (true, ResolveArgumentJson(parametersProp));
            }

            if (element.TryGetProperty("arguments", out var argumentsProp))
            {
                return (true, ResolveArgumentJson(argumentsProp));
            }

            if (element.TryGetProperty("args", out var argsProp))
            {
                return (true, ResolveArgumentJson(argsProp));
            }

            return (false, "{}");
        }

        private string ResolveArgumentJson(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    {
                        var raw = JsonSanitizer.SanitizeJson(element.GetString() ?? string.Empty);
                        if (string.IsNullOrWhiteSpace(raw))
                        {
                            return "{}";
                        }
                        try
                        {
                            using var doc = JsonDocument.Parse(raw);
                            return doc.RootElement.GetRawText();
                        }
                        catch (JsonException)
                        {
                            return JsonSerializer.Serialize(raw);
                        }
                    }
                case JsonValueKind.Object:
                case JsonValueKind.Array:
                    return element.GetRawText();
                case JsonValueKind.Null:
                case JsonValueKind.Undefined:
                    return "null";
                default:
                    return element.GetRawText();
            }
        }

        private bool TryParseFunctionEnvelope(string payload, out string functionName, out string json)
        {
            functionName = string.Empty;
            json = "{}";

            int openParen = payload.IndexOf('(');
            int closeParen = payload.LastIndexOf(')');
            if (openParen <= 0 || closeParen <= openParen)
            {
                return false;
            }

            functionName = payload.Substring(0, openParen).Trim();
            if (string.IsNullOrWhiteSpace(functionName))
            {
                return false;
            }

            var argsSegment = payload.Substring(openParen + 1, closeParen - openParen - 1).Trim();
            if (!TryConvertArgumentsToJson(argsSegment, out json))
            {
                json = "{}";
            }

            return true;
        }

        private bool TryConvertArgumentsToJson(string argsSegment, out string json)
        {
            json = "{}";

            if (string.IsNullOrWhiteSpace(argsSegment))
            {
                return true;
            }

            var kwargs = new Dictionary<string, object?>(StringComparer.Ordinal);
            var positional = new List<object?>();

            foreach (var rawArgument in SplitTopLevelArguments(argsSegment))
            {
                if (string.IsNullOrWhiteSpace(rawArgument))
                {
                    continue;
                }

                if (TrySplitKeyValue(rawArgument, out var key, out var valueExpression))
                {
                    if (!TryParseValue(valueExpression, out var parsedValue))
                    {
                        parsedValue = valueExpression.Trim();
                    }
                    kwargs[key] = parsedValue;
                }
                else
                {
                    if (!TryParseValue(rawArgument, out var parsedValue))
                    {
                        parsedValue = rawArgument.Trim();
                    }
                    positional.Add(parsedValue);
                }
            }

            object payload;

            if (kwargs.Count > 0 && positional.Count > 0)
            {
                payload = new Dictionary<string, object?>
                {
                    ["args"] = positional,
                    ["kwargs"] = kwargs
                };
            }
            else if (kwargs.Count > 0)
            {
                payload = kwargs;
            }
            else if (positional.Count > 0)
            {
                payload = positional;
            }
            else
            {
                return true;
            }

            json = JsonSerializer.Serialize(payload);
            return true;
        }

        private static IEnumerable<string> SplitTopLevelArguments(string args)
        {
            var parts = new List<string>();
            if (string.IsNullOrEmpty(args))
            {
                return parts;
            }

            var current = new System.Text.StringBuilder();
            int depthParentheses = 0;
            int depthBraces = 0;
            int depthBrackets = 0;
            bool inString = false;
            char stringDelimiter = '\0';

            for (int i = 0; i < args.Length; i++)
            {
                char ch = args[i];

                if (inString)
                {
                    current.Append(ch);
                    if (ch == stringDelimiter && !IsEscaped(args, i))
                    {
                        inString = false;
                    }
                    continue;
                }

                switch (ch)
                {
                    case '\'':
                    case '"':
                        inString = true;
                        stringDelimiter = ch;
                        current.Append(ch);
                        break;
                    case '(':
                        depthParentheses++;
                        current.Append(ch);
                        break;
                    case ')':
                        depthParentheses = Math.Max(0, depthParentheses - 1);
                        current.Append(ch);
                        break;
                    case '{':
                        depthBraces++;
                        current.Append(ch);
                        break;
                    case '}':
                        depthBraces = Math.Max(0, depthBraces - 1);
                        current.Append(ch);
                        break;
                    case '[':
                        depthBrackets++;
                        current.Append(ch);
                        break;
                    case ']':
                        depthBrackets = Math.Max(0, depthBrackets - 1);
                        current.Append(ch);
                        break;
                    case ',' when depthParentheses == 0 && depthBraces == 0 && depthBrackets == 0:
                        parts.Add(current.ToString().Trim());
                        current.Clear();
                        break;
                    default:
                        current.Append(ch);
                        break;
                }
            }

            if (current.Length > 0)
            {
                parts.Add(current.ToString().Trim());
            }

            return parts;
        }

        private static bool TrySplitKeyValue(string argument, out string key, out string value)
        {
            key = string.Empty;
            value = string.Empty;

            int depthParentheses = 0;
            int depthBraces = 0;
            int depthBrackets = 0;
            bool inString = false;
            char stringDelimiter = '\0';

            for (int i = 0; i < argument.Length; i++)
            {
                var ch = argument[i];

                if (inString)
                {
                    if (ch == stringDelimiter && !IsEscaped(argument, i))
                    {
                        inString = false;
                    }
                    continue;
                }

                switch (ch)
                {
                    case '\'':
                    case '"':
                        inString = true;
                        stringDelimiter = ch;
                        break;
                    case '(':
                        depthParentheses++;
                        break;
                    case ')':
                        depthParentheses = Math.Max(0, depthParentheses - 1);
                        break;
                    case '{':
                        depthBraces++;
                        break;
                    case '}':
                        depthBraces = Math.Max(0, depthBraces - 1);
                        break;
                    case '[':
                        depthBrackets++;
                        break;
                    case ']':
                        depthBrackets = Math.Max(0, depthBrackets - 1);
                        break;
                    case '=' when depthParentheses == 0 && depthBraces == 0 && depthBrackets == 0:
                        key = argument[..i].Trim();
                        value = argument[(i + 1)..].Trim();
                        return !string.IsNullOrEmpty(key);
                }
            }

            return false;
        }

        private static bool TryParseValue(string expression, out object? value)
        {
            expression = expression.Trim();
            value = null;

            if (string.IsNullOrEmpty(expression))
            {
                return true;
            }

            if ((expression.StartsWith("\"") && expression.EndsWith("\"")) ||
                (expression.StartsWith("'") && expression.EndsWith("'")))
            {
                value = ParseStringLiteral(expression);
                return true;
            }

            if (string.Equals(expression, "null", StringComparison.OrdinalIgnoreCase))
            {
                value = null;
                return true;
            }

            if (string.Equals(expression, "true", StringComparison.OrdinalIgnoreCase))
            {
                value = true;
                return true;
            }

            if (string.Equals(expression, "false", StringComparison.OrdinalIgnoreCase))
            {
                value = false;
                return true;
            }

            if (long.TryParse(expression, NumberStyles.Integer, CultureInfo.InvariantCulture, out var longValue))
            {
                value = longValue;
                return true;
            }

            if (double.TryParse(expression, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out var doubleValue))
            {
                value = doubleValue;
                return true;
            }

            if (expression.StartsWith("{", StringComparison.Ordinal) || expression.StartsWith("[", StringComparison.Ordinal))
            {
                var sanitized = JsonSanitizer.SanitizeJson(expression);
                try
                {
                    using var doc = JsonDocument.Parse(sanitized);
                    value = doc.RootElement.Clone();
                    return true;
                }
                catch (JsonException)
                {
                    value = sanitized;
                    return true;
                }
            }

            value = expression;
            return true;
        }

        private static string ParseStringLiteral(string literal)
        {
            if (literal.Length < 2)
            {
                return literal;
            }

            if (literal[0] == '"' && literal[^1] == '"')
            {
                try
                {
                    return JsonSerializer.Deserialize<string>(literal) ?? string.Empty;
                }
                catch (JsonException)
                {
                    return literal.Substring(1, literal.Length - 2);
                }
            }

            return ParseSingleQuotedString(literal);
        }

        private static string ParseSingleQuotedString(string literal)
        {
            var builder = new System.Text.StringBuilder();
            for (int i = 1; i < literal.Length - 1; i++)
            {
                var ch = literal[i];
                if (ch == '\\' && i + 1 < literal.Length - 1)
                {
                    i++;
                    var next = literal[i];
                    builder.Append(next switch
                    {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '\\' => '\\',
                        '\'' => '\'',
                        '"' => '"',
                        _ => next
                    });
                }
                else
                {
                    builder.Append(ch);
                }
            }
            return builder.ToString();
        }

        private static bool IsEscaped(string source, int index)
        {
            int escapeCount = 0;
            for (int i = index - 1; i >= 0 && source[i] == '\\'; i--)
            {
                escapeCount++;
            }
            return escapeCount % 2 == 1;
        }
    }
}

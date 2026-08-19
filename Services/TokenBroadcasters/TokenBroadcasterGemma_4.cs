using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    /// Broadcaster for Gemma-4 models. Parses the Gemma-4 native tool call format:
    /// <|tool_call>call:function_name{arg1:value1,arg2:value2}<tool_call|>
    /// and tool response format:
    /// <|tool_response>response:tool_name{key:value}<tool_response|>
    /// </summary>
    public sealed class TokenBroadcasterGemma_4 : TokenBroadcasterBase
    {
        public TokenBroadcasterGemma_4(
            ILLMResponseProcessor responseProcessor,
            ILogger logger,
            bool xmlFunctionParsing,
            HashSet<string> ignoreParameters)
            : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters) { }

        // --------------------------------------------------------------------
        //  MAIN PARSER
        // --------------------------------------------------------------------
        public override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            input = RemoveThinking(input, "think");

            var results = new List<(string json, string functionName)>();

            // Match <|tool_call>call:function_name{...}<tool_call|>
            var toolCallRegex = new Regex(@"<\|tool_call\>call:([A-Za-z_][A-Za-z0-9_]*)\s*(\{.*?\})\s*<tool_call\|>",
                                          RegexOptions.Singleline);

            foreach (Match m in toolCallRegex.Matches(input))
            {
                var funcName = m.Groups[1].Value;
                var argString = m.Groups[2].Value;

                try
                {
                    // Parse the argument object - Gemma-4 uses a Python-like dict syntax
                    var argsDict = ParseGemmaDict(argString);
                    argsDict["args_escaped"] = false;

                    var json = JsonConvert.SerializeObject(
                                   argsDict,
                                   Formatting.None,
                                   new JsonSerializerSettings { NullValueHandling = NullValueHandling.Include });

                    results.Add((json, funcName));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse Gemma-4 tool call arguments: {Arguments}", argString);
                }
            }

            return results;
        }

        // --------------------------------------------------------------------
        //  HELPERS
        // --------------------------------------------------------------------

        /// <summary>
        /// Parse Gemma-4's Python-like dictionary syntax into a .NET dictionary.
        /// Handles strings delimited by <|"|>, booleans (true/false), null, numbers, nested dicts and arrays.
        /// </summary>
        private Dictionary<string, object?> ParseGemmaDict(string input)
        {
            var dict = new Dictionary<string, object?>();

            // Remove outer braces if present
            var trimmed = input.Trim();
            if (trimmed.StartsWith("{") && trimmed.EndsWith("}"))
            {
                trimmed = trimmed.Substring(1, trimmed.Length - 2).Trim();
            }

            if (string.IsNullOrEmpty(trimmed))
            {
                return dict;
            }

            // Split by commas at top level
            var parts = SplitTopLevel(trimmed, ',');

            foreach (var part in parts)
            {
                var colonIndex = FindTopLevelChar(part, ':');
                if (colonIndex == -1) continue;

                var key = ParseKey(part.Substring(0, colonIndex));
                var value = ParseGemmaValue(part.Substring(colonIndex + 1).Trim());

                dict[key] = value;
            }

            return dict;
        }

        /// <summary>
        /// Parse a key, removing <|"|> delimiters if present.
        /// </summary>
        private static string ParseKey(string keyStr)
        {
            keyStr = keyStr.Trim();

            // Check for <|"|> delimiters
            if (keyStr.StartsWith("<|\"|>") && keyStr.EndsWith("<|\"|>"))
            {
                return keyStr.Substring(5, keyStr.Length - 10);
            }

            return keyStr;
        }

        /// <summary>
        /// Parse a Gemma-4 value which can be:
        /// - String: <|"|>value<|"|> or regular quoted string
        /// - Boolean: true/false
        /// - Null: null/None
        /// - Number: int or float
        /// - Array: [...]
        /// - Object: {...}
        /// </summary>
        private object? ParseGemmaValue(string valueStr)
        {
            valueStr = valueStr.Trim();

            if (string.IsNullOrEmpty(valueStr))
            {
                return null;
            }

            // Check for <|"|> string delimiter (Gemma-4 specific)
            if (valueStr.StartsWith("<|\"|>") && valueStr.EndsWith("<|\"|>"))
            {
                return valueStr.Substring(5, valueStr.Length - 10);
            }

            // Regular quoted strings
            if ((valueStr.StartsWith("'") && valueStr.EndsWith("'")) ||
                (valueStr.StartsWith("\"") && valueStr.EndsWith("\"")))
            {
                return valueStr.Substring(1, valueStr.Length - 2);
            }

            // Boolean
            if (valueStr.Equals("true", StringComparison.OrdinalIgnoreCase)) return true;
            if (valueStr.Equals("false", StringComparison.OrdinalIgnoreCase)) return false;

            // Null
            if (valueStr.Equals("null", StringComparison.OrdinalIgnoreCase) ||
                valueStr.Equals("none", StringComparison.OrdinalIgnoreCase)) return null;

            // Array
            if (valueStr.StartsWith("[") && valueStr.EndsWith("]"))
            {
                return ParseGemmaArray(valueStr);
            }

            // Nested object
            if (valueStr.StartsWith("{") && valueStr.EndsWith("}"))
            {
                return ParseGemmaDict(valueStr);
            }

            // Number
            if (valueStr.Contains("."))
            {
                if (double.TryParse(valueStr, NumberStyles.Any, CultureInfo.InvariantCulture, out var d))
                    return d;
            }
            else
            {
                if (long.TryParse(valueStr, NumberStyles.Any, CultureInfo.InvariantCulture, out var l))
                    return l;
            }

            // Fallback: treat as string
            return valueStr;
        }

        /// <summary>
        /// Parse a Gemma-4 array syntax.
        /// </summary>
        private List<object?> ParseGemmaArray(string input)
        {
            var list = new List<object?>();

            // Remove outer brackets
            var trimmed = input.Trim();
            if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
            {
                trimmed = trimmed.Substring(1, trimmed.Length - 2).Trim();
            }

            if (string.IsNullOrEmpty(trimmed))
            {
                return list;
            }

            // Split by commas at top level
            var parts = SplitTopLevel(trimmed, ',');

            foreach (var part in parts)
            {
                list.Add(ParseGemmaValue(part.Trim()));
            }

            return list;
        }

        /// <summary>
        /// Split a string by a delimiter character at the top level, respecting nesting and strings.
        /// </summary>
        private static List<string> SplitTopLevel(string s, char delimiter)
        {
            var parts = new List<string>();
            var sb = new StringBuilder();
            int depth = 0;
            bool inSingleQuote = false;
            bool inDoubleQuote = false;
            bool inGemmaString = false;

            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];

                // Check for Gemma-4 string delimiter <|"|>
                if (!inSingleQuote && !inDoubleQuote && i + 4 <= s.Length && s.Substring(i, 5) == "<|\"|>")
                {
                    inGemmaString = !inGemmaString;
                    sb.Append(s.Substring(i, 5));
                    i += 4;
                    continue;
                }

                if (c == '\'' && !inDoubleQuote && !inGemmaString) inSingleQuote = !inSingleQuote;
                else if (c == '"' && !inSingleQuote && !inGemmaString) inDoubleQuote = !inDoubleQuote;

                if (!inSingleQuote && !inDoubleQuote && !inGemmaString)
                {
                    if (c == '{' || c == '[' || c == '(') depth++;
                    else if (c == '}' || c == ']' || c == ')') depth--;
                    else if (c == delimiter && depth == 0)
                    {
                        var t = sb.ToString().Trim();
                        if (t.Length > 0) parts.Add(t);
                        sb.Clear();
                        continue;
                    }
                }

                sb.Append(c);
            }

            var final = sb.ToString().Trim();
            if (final.Length > 0) parts.Add(final);

            return parts;
        }

        /// <summary>
        /// Find the index of a character at the top level (not inside strings or nested structures).
        /// </summary>
        private static int FindTopLevelChar(string s, char target)
        {
            int depth = 0;
            bool inSingleQuote = false;
            bool inDoubleQuote = false;
            bool inGemmaString = false;

            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];

                // Check for Gemma-4 string delimiter <|"|>
                if (!inSingleQuote && !inDoubleQuote && i + 4 <= s.Length && s.Substring(i, 5) == "<|\"|>")
                {
                    inGemmaString = !inGemmaString;
                    i += 4;
                    continue;
                }

                if (c == '\'' && !inDoubleQuote && !inGemmaString) inSingleQuote = !inSingleQuote;
                else if (c == '"' && !inSingleQuote && !inGemmaString) inDoubleQuote = !inDoubleQuote;

                if (!inSingleQuote && !inDoubleQuote && !inGemmaString)
                {
                    if (c == '{' || c == '[' || c == '(') depth++;
                    else if (c == '}' || c == ']' || c == ')') depth--;
                    else if (c == target && depth == 0)
                    {
                        return i;
                    }
                }
            }

            return -1;
        }
    }
}

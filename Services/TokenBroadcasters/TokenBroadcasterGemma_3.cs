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
    /// Broadcaster for Gemma-3 models.  Converts ```tool_code``` Python calls
    /// into (json,functionName) tuples used by the Network Monitor pipeline.
    /// Robust against in-block # comments.
    /// </summary>
    public sealed class TokenBroadcasterGemma_3 : TokenBroadcasterBase
    {
        public TokenBroadcasterGemma_3(
            ILLMResponseProcessor responseProcessor,
            ILogger logger,
            bool xmlFunctionParsing,
            HashSet<string> ignoreParameters)
            : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters) { }

        // --------------------------------------------------------------------
        //  MAIN PARSER (updated)
        // --------------------------------------------------------------------
        public override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            input = RemoveThinking(input, "think");

            var results = new List<(string json, string functionName)>();

            // Find every ```tool_code ...``` block
            var blockRegex = new Regex(@"```tool_code\s*(.*?)\s*```",
                                       RegexOptions.Singleline);
            foreach (Match m in blockRegex.Matches(input))
            {
                var codeLine = m.Groups[1].Value.Trim();
                if (string.IsNullOrEmpty(codeLine)) continue;

                // Extract function name and arg list
                var callMatch = Regex.Match(codeLine,
                    @"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$",
                    RegexOptions.Singleline);

                if (!callMatch.Success) continue;   // malformed; ignore

                var funcName = callMatch.Groups[1].Value;
                var argString = StripComments(callMatch.Groups[2].Value);

                var argsDict = ParseArguments(argString);
                argsDict["args_escaped"] = false;      // mirror XML path

                var json = JsonConvert.SerializeObject(
                               argsDict,
                               Formatting.None,
                               new JsonSerializerSettings { NullValueHandling = NullValueHandling.Include });

                results.Add((json, funcName));
            }
            return results;
        }

        // --------------------------------------------------------------------
        //  HELPERS
        // --------------------------------------------------------------------

        /// <summary>
        /// Remove # comments that are outside single/double quotes.
        /// Keeps newlines so multi-line calls still parse.
        /// </summary>
        private static string StripComments(string s)
        {
            var sb = new StringBuilder();
            bool inSingle = false, inDouble = false;

            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];

                if (c == '\'' && !inDouble) inSingle = !inSingle;
                else if (c == '"' && !inSingle) inDouble = !inDouble;
                else if (c == '#' && !inSingle && !inDouble)
                {
                    // skip until end-of-line
                    while (i < s.Length && s[i] != '\n' && s[i] != '\r') i++;
                    // loop increment will move past newline
                    continue;
                }

                sb.Append(c);
            }
            return sb.ToString();
        }

        private Dictionary<string, object?> ParseArguments(string argString)
        {
            var dict = new Dictionary<string, object?>();

            foreach (var part in SplitTopLevel(argString))
            {
                var kv = part.Split('=', 2);
                if (kv.Length != 2) continue;

                var key = kv[0].Trim();
                var value = kv[1].Trim();
                dict[key] = ParseLiteral(value);
            }
            return dict;
        }

        /// <summary>
        /// Split comma-separated items at top level, respecting strings/brackets.
        /// </summary>
        private static IEnumerable<string> SplitTopLevel(string s)
        {
            var parts = new List<string>();
            var sb = new StringBuilder();
            int depth = 0; bool inSingle = false; bool inDouble = false;

            void flush()
            { var t = sb.ToString().Trim(); if (t.Length > 0) parts.Add(t); sb.Clear(); }

            foreach (char c in s)
            {
                if (c == '\'' && !inDouble) inSingle = !inSingle;
                else if (c == '"' && !inSingle) inDouble = !inDouble;
                else if (!inSingle && !inDouble)
                {
                    if ("([{".Contains(c)) depth++;
                    else if (")]}".Contains(c)) depth--;
                    else if (c == ',' && depth == 0) { flush(); continue; }
                }
                sb.Append(c);
            }
            flush();
            return parts;
        }

        private static object? ParseLiteral(string raw)
        {
            // Booleans / None
            if (raw.Equals("True", StringComparison.OrdinalIgnoreCase)) return true;
            if (raw.Equals("False", StringComparison.OrdinalIgnoreCase)) return false;
            if (raw.Equals("None", StringComparison.OrdinalIgnoreCase)) return null;

            // Quoted string
            if ((raw.StartsWith("'") && raw.EndsWith("'")) ||
                (raw.StartsWith("\"") && raw.EndsWith("\"")))
                return raw.Substring(1, raw.Length - 2);

            // Number
            if (raw.Contains('.'))
            {
                if (double.TryParse(raw, NumberStyles.Any, CultureInfo.InvariantCulture, out var d))
                    return d;
            }
            else
            {
                if (long.TryParse(raw, NumberStyles.Any, CultureInfo.InvariantCulture, out var l))
                    return l;
            }

            // Fallback: treat as string
            return raw;
        }
    }
}

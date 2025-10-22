
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    /// Parses GPT-OSS structured tool calls.
    /// Handles both of the known envelopes, for example:
    ///     <|start|>assistant to=functions.NAME<|channel|>commentary json<|message|>{...}<|call|>
    ///     function.commentary to=functions.NAME <|constrain|>json<|message|>{...}
    /// Also lets normal assistant text flow through to the base processor.
    /// </summary>
    public sealed class TokenBroadcasterGptOss : TokenBroadcasterBase
    {
        public TokenBroadcasterGptOss(
            ILLMResponseProcessor responseProcessor,
            ILogger logger,
            bool xmlFunctionParsing,
            HashSet<string> ignoreParameters)
            : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
        {
        }

        public override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var results = new List<(string json, string functionName)>();

          

            var segments = ExtractSegments(input);
            foreach (var segment in segments)
            {
                var functionName = ExtractFunctionName(segment);
                var payload = ExtractPayload(segment);

                if (string.IsNullOrWhiteSpace(payload))
                    continue;

                // Try to parse structured { "name": "...", "arguments": {...} } shape first.
                if (TryParseStructuredPayload(payload, out var structuredName, out var argumentsJson))
                {
                    var resolvedName = string.IsNullOrWhiteSpace(structuredName) ? functionName : structuredName;
                    if (string.IsNullOrWhiteSpace(resolvedName))
                        continue;

                    results.Add((argumentsJson ?? "{}", resolvedName));
                    continue;
                }

                // Fallback: use message payload as arguments and the extracted name as function.
                if (string.IsNullOrWhiteSpace(functionName))
                    continue;

                var repaired = JsonSanitizer.RepairJson(payload, _ignoreParameters);
                if (string.IsNullOrWhiteSpace(repaired))
                    continue;

                results.Add((repaired, functionName));
            }

            return results;
        }

        /// <summary>
        /// For GPT-OSS we don't need to strip extra headers from tool responses;
        /// keep hook available for future adjustments.
        /// </summary>
        protected override string StripExtraFuncHeader(string input) => input;

        private static IEnumerable<(string prefix, string message)> ExtractSegments(string input)
        {
            var pattern = new Regex(@"(?<prefix>.*?)(<\|message\|\>(?<message>[\s\S]*?))(?:$|(?=<\|message\|\>))", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            foreach (Match match in pattern.Matches(input))
            {
                var messageGroup = match.Groups["message"];
                if (!messageGroup.Success) continue;
                yield return (match.Groups["prefix"].Value, messageGroup.Value);
            }
        }

        private static string ExtractFunctionName((string prefix, string message) segment)
        {
            // Look for narrative "Use get_host_list function."
            var narrativeMatch = Regex.Match(segment.prefix, @"Use\s+(?<name>[A-Za-z0-9_.-]+)\s+function", RegexOptions.IgnoreCase);
            if (narrativeMatch.Success)
            {
                return NormalizeFunctionName("functions." + narrativeMatch.Groups["name"].Value);
            }

            // Look for explicit to=functions.xxx or function.xxx to=...
            var toMatch = Regex.Match(segment.prefix, @"(?:to=|function\.)\s*(?<dest>functions\.[A-Za-z0-9_.-]+)", RegexOptions.IgnoreCase);
            if (toMatch.Success)
            {
                return NormalizeFunctionName(toMatch.Groups["dest"].Value);
            }

            return string.Empty;
        }

        private static string ExtractPayload((string prefix, string message) segment)
        {
            var payload = segment.message;
            payload = payload.Trim();
            return payload;
        }

        private bool TryParseStructuredPayload(string payload, out string functionName, out string? argumentsJson)
        {
            functionName = string.Empty;
            argumentsJson = null;
            try
            {
                var token = JToken.Parse(payload);
                if (token.Type != JTokenType.Object) return false;

                var obj = (JObject)token;
                var nameToken = obj.Properties().FirstOrDefault(p => string.Equals(p.Name, "name", StringComparison.OrdinalIgnoreCase))?.Value;
                var argumentsToken = obj.Properties().FirstOrDefault(p =>
                    string.Equals(p.Name, "arguments", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(p.Name, "parameters", StringComparison.OrdinalIgnoreCase))?.Value;

                if (nameToken is JValue nameValue && nameValue.Type == JTokenType.String)
                {
                    functionName = NormalizeFunctionName(nameValue.Value<string>());
                }

                if (argumentsToken != null)
                {
                    if (argumentsToken.Type == JTokenType.String)
                    {
                        var argumentString = argumentsToken.Value<string>() ?? string.Empty;
                        argumentString = argumentString.Trim();
                        if (argumentString.Length == 0)
                        {
                            argumentsJson = "{}";
                        }
                        else if ((argumentString.StartsWith("{") && argumentString.EndsWith("}")) ||
                                 (argumentString.StartsWith("[") && argumentString.EndsWith("]")))
                        {
                            argumentsJson = JToken.Parse(argumentString).ToString(Formatting.None);
                        }
                        else
                        {
                            argumentsJson = JsonConvert.SerializeObject(argumentString);
                        }
                    }
                    else
                    {
                        argumentsJson = argumentsToken.ToString(Formatting.None);
                    }
                }
                else
                {
                    argumentsJson = "{}";
                }

                return !string.IsNullOrWhiteSpace(functionName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to parse structured GPT-OSS payload: {Payload}", payload);
                return false;
            }
        }
    }
}

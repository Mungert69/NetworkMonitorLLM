using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using System.Text.RegularExpressions;

namespace NetworkMonitor.LLM.Services
{
    public class TokenBroadcasterXlam2 : TokenBroadcasterBase
    {
        public TokenBroadcasterXlam2(
            ILLMResponseProcessor responseProcessor,
            ILogger logger,
            bool xmlFunctionParsing,
            HashSet<string> ignoreParameters)
            : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
        {
        }

        /// <summary>
        /// Parses JSON tool/function call(s) from the LLM output. Supports an array of calls.
        /// Each call should be like: {"name": "search", "arguments": {...}}
        /// </summary>
        public override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var functionCalls = new List<(string json, string functionName)>();

            if (string.IsNullOrWhiteSpace(input))
                return functionCalls;

            // Remove array brackets if present
            input = input.Trim();
            if (input.StartsWith("[") && input.EndsWith("]"))
                input = input.Substring(1, input.Length - 2);

            // Regex pattern to match tool call objects
            // Matches {"name": "...", "arguments": {...}}
            var pattern = @"{""name""\s*:\s*""(?<name>[^""]+)""\s*,\s*""arguments""\s*:\s*(?<arguments>{(?:[^{}]*|\{(?:[^{}]*|\{.*?\})*\})*})}";
            var matches = Regex.Matches(input, pattern, RegexOptions.Singleline);

            foreach (Match match in matches)
            {
                try
                {
                    var functionName = match.Groups["name"].Value;
                    var argumentsJson = match.Groups["arguments"].Value;

                    // Optionally sanitize/fix the JSON if needed
                    var sanitizedJson = JsonSanitizer.RepairJson(argumentsJson, _ignoreParameters) ?? "";

                    functionCalls.Add((sanitizedJson, functionName));
                    _logger.LogDebug("Parsed function call: {FunctionName}, JSON: {SanitizedJson}", functionName, sanitizedJson);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to parse or repair JSON block: {JsonBlock}", match.Value);
                }
            }

            return functionCalls;
        }

        // Optionally, you can override/extend this if you want additional repair logic
        private string TryRepairJson(string jsonContent)
        {
            // Remove extra braces, fix common issues
            if (jsonContent.StartsWith("{{") && jsonContent.EndsWith("}}"))
                jsonContent = jsonContent.TrimStart('{').TrimEnd('}');
            jsonContent = jsonContent.Replace("}{", "},{");
            jsonContent = jsonContent.Replace("\"{", "{").Replace("}\"", "}");
            return jsonContent;
        }
    }
}

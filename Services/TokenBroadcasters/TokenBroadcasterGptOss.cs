
using System.Text.RegularExpressions;
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

namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    /// Parses GPT-OSS structured tool calls:
    /// <|start|>assistant to=functions.NAME<|channel|>commentary [json] <|message|>{...}<|call|>
    /// Also lets normal assistant text flow through to the base processor.
    /// </summary>
    public sealed class TokenBroadcasterGptOss : TokenBroadcasterBase
    {
        // Match assistant → tool call envelope.
        // Examples:
        // <|start|>assistant to=functions.search<|channel|>commentary json<|message|>{"q":"x"}<|call|>
        // <|start|>assistant to=functions.foo.bar<|channel|>commentary<|message|>{...}<|call|>
        private static readonly Regex ToolCallRegex = new(
            @"<\|start\|\>assistant\s+to=(?<dest>functions\.[A-Za-z0-9_.-]+)\s*"
          + @"<\|channel\|\>commentary(?:\s+json)?\s*"
          + @"<\|message\|\>(?<args>.*?)<\|call\|>",
            RegexOptions.Singleline | RegexOptions.Compiled);

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
            var found = new List<(string json, string functionName)>();

            // Extract all tool-call envelopes present in the buffered output
            foreach (Match m in ToolCallRegex.Matches(input))
            {
                var fn = m.Groups["dest"].Value;   // e.g., functions.lookup
                var args = m.Groups["args"].Value; // raw args JSON inside <|message|>…<|call|>

                // Your sanitizer prunes ignored params (e.g., "source_code") & fixes minor JSON issues
                var repaired = JsonSanitizer.RepairJson(args, _ignoreParameters);

                if (!string.IsNullOrWhiteSpace(repaired))
                    found.Add((repaired, fn));
            }

            // If no envelopes matched, fall back to the base "first JSON object" sweep
            if (found.Count == 0)
                return base.ParseInputForJson(input);

            return found;
        }

        /// <summary>
        /// For GPT-OSS we don't need to strip extra headers from tool responses;
        /// keep hook available for future adjustments.
        /// </summary>
        protected override string StripExtraFuncHeader(string input) => input;
    }
}

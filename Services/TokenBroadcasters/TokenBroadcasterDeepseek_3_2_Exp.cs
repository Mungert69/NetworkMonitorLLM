using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services
{
    public sealed class TokenBroadcasterDeepseek_3_2_Exp : TokenBroadcasterBase
    {
        private const string ToolCallBegin = "<｜tool▁call▁begin｜>";
        private const string ToolCallEnd = "<｜tool▁call▁end｜>";
        private const string ToolSep = "<｜tool▁sep｜>";
        private const string ToolOutputBegin = "<｜tool▁output▁begin｜>";
        private const string ToolOutputEnd = "<｜tool▁output▁end｜>";

        public TokenBroadcasterDeepseek_3_2_Exp(
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

            var index = 0;
            while (true)
            {
                var callStart = input.IndexOf(ToolCallBegin, index, StringComparison.Ordinal);
                if (callStart < 0)
                {
                    break;
                }

                callStart += ToolCallBegin.Length;
                var callEnd = input.IndexOf(ToolCallEnd, callStart, StringComparison.Ordinal);
                if (callEnd < 0)
                {
                    break;
                }

                var callBody = input.Substring(callStart, callEnd - callStart).Trim();
                index = callEnd + ToolCallEnd.Length;

                if (!TryParseToolCall(callBody, out var functionName, out var argsJson))
                {
                    continue;
                }

                var sanitizedJson = JsonSanitizer.RepairJson(argsJson, _ignoreParameters) ?? "";
                functionCalls.Add((sanitizedJson, functionName));
            }

            if (functionCalls.Count == 0 && _xmlFunctionParsing)
            {
                return base.ParseInputForXml(input);
            }

            return functionCalls;
        }

        private static bool TryParseToolCall(string callBody, out string functionName, out string argsJson)
        {
            functionName = "";
            argsJson = "";

            if (string.IsNullOrWhiteSpace(callBody))
            {
                return false;
            }

            var sepIndex = callBody.IndexOf(ToolSep, StringComparison.Ordinal);
            if (sepIndex < 0)
            {
                return false;
            }

            functionName = callBody.Substring(0, sepIndex).Trim();
            if (string.IsNullOrWhiteSpace(functionName))
            {
                return false;
            }

            var remainder = callBody.Substring(sepIndex + ToolSep.Length).Trim();
            if (string.IsNullOrWhiteSpace(remainder))
            {
                return false;
            }

            argsJson = ExtractArgumentsJson(remainder);
            return !string.IsNullOrWhiteSpace(argsJson);
        }

        private static string ExtractArgumentsJson(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return "";
            }

            var outputStart = text.IndexOf(ToolOutputBegin, StringComparison.Ordinal);
            if (outputStart >= 0)
            {
                var outputEnd = text.IndexOf(ToolOutputEnd, outputStart + ToolOutputBegin.Length, StringComparison.Ordinal);
                if (outputEnd > outputStart)
                {
                    text = text.Substring(0, outputStart);
                }
            }

            var firstBrace = text.IndexOf('{');
            var lastBrace = text.LastIndexOf('}');
            if (firstBrace >= 0 && lastBrace > firstBrace)
            {
                return text.Substring(firstBrace, lastBrace - firstBrace + 1).Trim();
            }

            return text.Trim();
        }
    }
}

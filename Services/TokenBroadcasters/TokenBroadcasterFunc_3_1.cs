using System;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using System.Linq;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;

namespace NetworkMonitor.LLM.Services
{
    public class TokenBroadcasterFunc_3_1 : TokenBroadcasterBase
    {

        public TokenBroadcasterFunc_3_1(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
             : base(responseProcessor, logger)
        {
            _xmlFunctionParsing = xmlFunctionParsing;
            _userReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n";
            _functionReplace = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n";
            _assistantHeader="<|start_header_id|>assistant<|end_header_id|>";
            _endTokens.Add("<|eot_id|>");
            _endTokens.Add("<|eom_id|>");
        }



        protected override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var functionCalls = new List<(string json, string functionName)>();

            // Extract individual function call blocks using your custom method
            var functionCallExtracts = ExtractFunctionCalls(input);

            // Process each function call block
            foreach (var functionCallExtract in functionCallExtracts)
            {
                var processedCall = ProcessFunctionCall(functionCallExtract);
                if (processedCall != null)
                {
                    functionCalls.Add((processedCall.Value.json, processedCall.Value.functionName));
                }
            }

            return functionCalls;
        }

        private (string json, string functionName)? ProcessFunctionCall(string functionCall)
        {
            var match = Regex.Match(functionCall, @"<function=(\w+)>(.*?)</function>");
            if (match.Success)
            {
                string functionName = match.Groups[1].Value;
                string jsonArguments = match.Groups[2].Value;
                return (jsonArguments, functionName);

            }
            return null;
        }

        private List<string> ExtractFunctionCalls(string input)
        {
            return Regex.Matches(input, @"<function=\w+>.*?</function>")
                        .OfType<Match>()
                        .Select(m => m.Value)
                        .ToList();
        }
        private string RemoveFunctionCalls(string input)
        {
            return Regex.Replace(input, @"<function=\w+>.*?</function>", "").Trim();
        }
    }
}
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
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterPhi_4 : TokenBroadcasterBase
{

    public TokenBroadcasterPhi_4(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
        : base(responseProcessor, logger,xmlFunctionParsing)
    {
        
    }

       protected override string StripExtraFuncHeader(string input)
    {
        return input.Replace("\\\n</function_response", "");

    }

  public override List<(string json, string functionName)> ParseInputForJson(string input)
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
            // note the regex is forgiving to </function> or <function> the = used to delimit the start
            var match = Regex.Match(functionCall, @"</?function(?:=(\w+))?>(.*?)</?function>");
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
            return Regex.Matches(input, @"</?function=\w+>.*?</?function>")
                        .OfType<Match>()
                        .Select(m => m.Value)
                        .ToList();
        }
        private string RemoveFunctionCalls(string input)
        {
            return Regex.Replace(input, @"</?function=\w+>.*?</?function>", "").Trim();
        }
}
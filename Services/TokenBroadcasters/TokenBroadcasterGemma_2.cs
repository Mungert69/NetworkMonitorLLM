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
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterGemma_2 : TokenBroadcasterBase
{

    public TokenBroadcasterGemma_2(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
         : base(responseProcessor, logger,xmlFunctionParsing)
    {

    }
   

       public override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var functionsCalls = new List<(string json, string functionName)>();
            if (input.Contains("Funtion response:"))
            {
                functionsCalls.Add((input, ""));
                return functionsCalls;
            }
            string newLine = string.Empty;
            // bool foundStart = false;
            bool foundEnd = false;
            int startIndex = input.IndexOf('{');
            // If '{' is not found or is too far into the input, return the original input
            if (startIndex == -1)
            {
                functionsCalls.Add((input, ""));
                return functionsCalls;
            }
            newLine = input.Substring(startIndex);
            int lastClosingBraceIndex = newLine.LastIndexOf('}');
            if (lastClosingBraceIndex != -1)
            {
                newLine = newLine.Substring(0, lastClosingBraceIndex + 1);
                foundEnd = true;
            }
            if (foundEnd)
            {
                functionsCalls.Add((JsonSanitizer.SanitizeJson(newLine), ""));
                return functionsCalls;
            }
            else
            {
                functionsCalls.Add((input, ""));
                return functionsCalls;
            }
        }

}
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
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterFunc_3_2 : TokenBroadcasterBase
{

    public TokenBroadcasterFunc_3_2(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
         : base(responseProcessor, logger,xmlFunctionParsing)
    {

    }

   
    // Updated ParseInputForJson to handle multiple function calls
    public override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        var functionCalls = new List<(string json, string functionName)>();

        int tagStart = input.IndexOf(_assistantHeader);
        while (tagStart != -1)
        {
            int tagStartLength = $"{_assistantHeader}\n\n>>>all\n".Length;
            string noHeaderLine = input.Substring(tagStart + tagStartLength).Trim();

            int headerStart = noHeaderLine.IndexOf(">>>");
            if (headerStart == -1) break;

            noHeaderLine = noHeaderLine.Substring(headerStart + 3);
            int headerEnd = noHeaderLine.IndexOf('\n');
            if (headerEnd == -1) break;

            string functionName = noHeaderLine.Substring(0, headerEnd).Trim();
            int jsonStart = headerEnd + 1;
            int jsonEnd = noHeaderLine.IndexOf("<|eot_id|>", jsonStart);

            if (jsonEnd == -1) break;

            string jsonContent = noHeaderLine.Substring(jsonStart, jsonEnd - jsonStart).Trim();
            functionCalls.Add((JsonSanitizer.SanitizeJson(jsonContent), functionName));

            // Move to the next function call in the input (if any)
            tagStart = input.IndexOf(_assistantHeader, jsonEnd);
        }

        return functionCalls;
    }


}
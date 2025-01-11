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
public class TokenBroadcasterFunc_2_5 : TokenBroadcasterBase
{

    public TokenBroadcasterFunc_2_5(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
         : base(responseProcessor, logger,xmlFunctionParsing)
    {
    
    }




    protected override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        string specialToken = "<|reserved_special_token_249|>";
        var functionCalls = new List<(string json, string functionName)>();

        int currentIndex = 0;
        while (true)
        {
            // Find the special token
            int tokenIndex = input.IndexOf(specialToken, currentIndex);
            if (tokenIndex == -1)
            {
                break; // No more special tokens found
            }

            // Extract the string after the special token
            string postTokenString = input.Substring(tokenIndex + specialToken.Length);

            // Find the start index of the JSON content
            int jsonStartIndex = postTokenString.IndexOf('{');
            if (jsonStartIndex == -1)
            {
                currentIndex = tokenIndex + specialToken.Length;
                continue; // No JSON found; move to the next token
            }

            // Extract the function name (content before JSON start)
            string functionNamePart = postTokenString.Substring(0, jsonStartIndex);
            string functionName = functionNamePart.Replace("\n", "").Trim();

            // Extract the JSON content
            string jsonContent = postTokenString.Substring(jsonStartIndex);

            // Find the end of the JSON content
            int jsonEndIndex = jsonContent.LastIndexOf('}');
            if (jsonEndIndex != -1)
            {
                jsonContent = jsonContent.Substring(0, jsonEndIndex + 1);
            }
            else
            {
                currentIndex = tokenIndex + specialToken.Length;
                continue; // Malformed JSON; move to the next token
            }

            // Sanitize and add the extracted JSON and function name to the list
            functionCalls.Add((JsonSanitizer.SanitizeJson(jsonContent), functionName));

            // Update currentIndex to continue searching after this function call
            currentIndex = tokenIndex + specialToken.Length + jsonEndIndex + 1;
        }

        return functionCalls;
    }

}
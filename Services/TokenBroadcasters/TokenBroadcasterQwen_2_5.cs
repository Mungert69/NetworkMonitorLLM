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
public class TokenBroadcasterQwen_2_5 : TokenBroadcasterBase
{

    public TokenBroadcasterQwen_2_5(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing, HashSet<string> ignoreParameters)
        : base(responseProcessor, logger,xmlFunctionParsing,ignoreParameters)
    {

    }
    protected override string StripExtraFuncHeader(string input)
    {
        return input.Replace("\\\n</tool_response", "");

    }


    public override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        input=RemoveThinking(input,"think");
        var functionCalls = new List<(string json, string functionName)>();
        int tagStart = input.IndexOf("<tool_call>\n");
        int tagEnd;

        while (tagStart != -1)
        {
            // Move the starting index after the "<tool_call>\n" tag
            tagStart += "<tool_call>\n".Length;
            tagEnd = input.IndexOf("\n</tool_call>", tagStart);

            // If no matching end tag is found, break the loop
            if (tagEnd == -1) break;

            // Extract the JSON content between the tags
            string jsonContent = input.Substring(tagStart, tagEnd - tagStart).Trim();
            functionCalls.Add((JsonSanitizer.RepairJson(jsonContent,_ignoreParameters), string.Empty));

            // Look for the next "<tool_call>\n" tag after the current end tag
            tagStart = input.IndexOf("<tool_call>\n", tagEnd + "</tool_call>".Length);
        }

        return functionCalls;
    }

}
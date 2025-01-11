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
   

    protected override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        var functionCalls = new List<(string json, string functionName)>();

        // Define regex pattern to capture the function name and parameters JSON block
        var pattern = @"{""name"":\s*""(?<name>[^""]+)"",\s*""parameters"":\s*(?<parameters>{.*?})}";
        var matches = Regex.Matches(input, pattern);

        foreach (Match match in matches)
        {
            // Get function name and JSON parameters block
            var functionName = match.Groups["name"].Value;
            var jsonContent = match.Groups["parameters"].Value;

            // Optionally sanitize the JSON content
            functionCalls.Add((JsonSanitizer.SanitizeJson(jsonContent), functionName));
        }

        return functionCalls;
    }

}
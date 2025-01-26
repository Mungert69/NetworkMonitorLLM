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
public class TokenBroadcasterLlama_3_2 : TokenBroadcasterBase
{

    public TokenBroadcasterLlama_3_2(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing, HashSet<string> ignoreParameters)
         : base(responseProcessor, logger,xmlFunctionParsing,ignoreParameters)
    {
       
    }
   

   /* public override List<(string json, string functionName)> ParseInputForJson(string input)
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
            functionCalls.Add((JsonSanitizer.RepairJson(jsonContent,_ignoreParameters), functionName));
        }

        return functionCalls;
    }*/
public override List<(string json, string functionName)> ParseInputForJson(string input)
{
    var functionCalls = new List<(string json, string functionName)>();

    // Regex to match the entire JSON block containing "name" and "parameters"
    var pattern = @"{""name""\s*:\s*""(?<name>[^""]+)"",\s*""parameters""\s*:\s*(?<parameters>{(?:[^{}]*|\{(?:[^{}]*|\{.*?\})*\})*})}";
    var matches = Regex.Matches(input, pattern);

    foreach (Match match in matches)
    {
        try
        {
            // Capture the entire JSON block (name + parameters)
            var entireJson = match.Value;

            // Attempt to repair the entire JSON block
            var repairedJson = JsonSanitizer.RepairJson(entireJson, _ignoreParameters);

            // Parse the repaired JSON into a structured object
            using var document = JsonDocument.Parse(repairedJson);
            var root = document.RootElement;

            // Extract the function name
            var functionName = root.GetProperty("name").GetString();

            // Extract the parameters as JSON
            var parametersElement = root.GetProperty("parameters");
            var parametersJson = parametersElement.GetRawText();

            // Optionally sanitize the JSON parameters
            var sanitizedJson = JsonSanitizer.RepairJson(parametersJson, _ignoreParameters);

            // Add the parsed result to the list
            functionCalls.Add((sanitizedJson, functionName));

            // Debug logging
            _logger.LogDebug("Parsed and repaired function call: {FunctionName}, JSON: {SanitizedJson}", functionName, sanitizedJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse or repair JSON block: {JsonBlock}", match.Value);
        }
    }

    return functionCalls;
}

private string TryRepairJson(string jsonContent)
{
    // Example: Remove extra braces around the entire JSON block
    if (jsonContent.StartsWith("{{") && jsonContent.EndsWith("}}"))
    {
        jsonContent = jsonContent.TrimStart('{').TrimEnd('}');
    }

    // Use additional strategies for common issues (e.g., missing commas, unescaped quotes)
    jsonContent = jsonContent.Replace("}{", "},{"); // Fix concatenated objects
    jsonContent = jsonContent.Replace("\"{", "{").Replace("}\"", "}"); // Fix incorrect quotes around JSON

    // Add more repair logic as needed
    return jsonContent;
}


}
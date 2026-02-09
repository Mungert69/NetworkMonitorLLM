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
         : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
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
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(input))
        {
            return functionCalls;
        }
        // Use a regular expression to remove the "type": "function" part ONLY at the start of the input
        input = Regex.Replace(input, @"^\s*{\s*""type""\s*:\s*""function""\s*,?\s*", "{");
        // Normalize pretty-printed JSON so "{" immediately precedes ""name"".
        input = Regex.Replace(input, @"{\s*(?=""name"")", "{");

        foreach (var candidate in ExtractJsonObjects(input))
        {
            if (!LooksLikeFunctionCallCandidate(candidate))
            {
                continue;
            }
            try
            {
                // Attempt to repair the entire JSON block
                var repairedJson = JsonSanitizer.RepairJson(candidate, _ignoreParameters);

                // Parse the repaired JSON into a structured object
                using var document = JsonDocument.Parse(repairedJson);
                var root = document.RootElement;

                if (!TryExtractFunctionCall(root, out var functionName, out var parametersJson))
                {
                    continue;
                }
                // Optionally sanitize the JSON parameters
                var sanitizedJson = JsonSanitizer.RepairJson(parametersJson, _ignoreParameters) ?? "";

                // Add the parsed result to the list
                var key = $"{functionName}\n{sanitizedJson}";
                if (seen.Add(key))
                {
                    functionCalls.Add((sanitizedJson, functionName));
                }

                // Debug logging
                _logger.LogDebug("Parsed and repaired function call: {FunctionName}, JSON: {SanitizedJson}", functionName, sanitizedJson);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to parse or repair JSON block: {JsonBlock}", candidate);
            }
        }

        return functionCalls;
    }

    private static bool LooksLikeFunctionCallCandidate(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }
        return json.Contains("\"name\"")
               && (json.Contains("\"parameters\"") || json.Contains("\"arguments\"") || json.Contains("\"function\""));
    }

    private static IEnumerable<string> ExtractJsonObjects(string input)
    {
        var stack = new Stack<int>();
        var inString = false;
        var escape = false;

        for (var i = 0; i < input.Length; i++)
        {
            var c = input[i];
            if (inString)
            {
                if (escape)
                {
                    escape = false;
                    continue;
                }
                if (c == '\\')
                {
                    escape = true;
                    continue;
                }
                if (c == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (c == '"')
            {
                inString = true;
                continue;
            }

            if (c == '{')
            {
                stack.Push(i);
                continue;
            }

            if (c == '}')
            {
                if (stack.Count > 0)
                {
                    var start = stack.Pop();
                    yield return input.Substring(start, i - start + 1);
                }
            }
        }
    }

    private static bool TryExtractFunctionCall(JsonElement element, out string functionName, out string parametersJson)
    {
        functionName = "";
        parametersJson = "";

        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        return TryExtractFromObject(element, out functionName, out parametersJson);
    }

    private static bool TryExtractFromObject(JsonElement element, out string functionName, out string parametersJson)
    {
        functionName = "";
        parametersJson = "";

        if (element.TryGetProperty("name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String)
        {
            if (element.TryGetProperty("parameters", out var parametersElement) ||
                element.TryGetProperty("arguments", out parametersElement))
            {
                functionName = nameElement.GetString() ?? "";
                parametersJson = ExtractParametersJson(parametersElement);
                return !string.IsNullOrEmpty(functionName);
            }
        }

        if (element.TryGetProperty("function", out var functionElement) && functionElement.ValueKind == JsonValueKind.Object)
        {
            return TryExtractFromObject(functionElement, out functionName, out parametersJson);
        }

        return false;
    }

    private static string ExtractParametersJson(JsonElement parametersElement)
    {
        if (parametersElement.ValueKind == JsonValueKind.String)
        {
            return parametersElement.GetString() ?? "";
        }
        return parametersElement.GetRawText();
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

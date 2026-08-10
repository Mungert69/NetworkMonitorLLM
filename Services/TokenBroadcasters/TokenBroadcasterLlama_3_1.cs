using System;
using System.Text.Json;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using System.Text.RegularExpressions;

namespace NetworkMonitor.LLM.Services;

public class TokenBroadcasterLlama_3_1 : TokenBroadcasterBase
{
    private const string EotToken = "<|eot_id|>";
    private const string EomToken = "<|eom_id|>";

    public TokenBroadcasterLlama_3_1(
        ILLMResponseProcessor responseProcessor,
        ILogger logger,
        bool xmlFunctionParsing,
        HashSet<string> ignoreParameters)
        : base(
            responseProcessor,
            logger,
            xmlFunctionParsing,
            ignoreParameters)
    {
    }

    public override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        var functionCalls = new List<(string json, string functionName)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        if (string.IsNullOrWhiteSpace(input))
        {
            return functionCalls;
        }

        input = NormalizeLlama31Output(input);

        foreach (var functionCall in ExtractFunctionCalls(input))
        {
            try
            {
                var functionName = functionCall.functionName.Trim();
                var argumentsJson = functionCall.argumentsJson.Trim();

                if (string.IsNullOrWhiteSpace(functionName))
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(argumentsJson))
                {
                    argumentsJson = "{}";
                }

                /*
                 * Repair the argument JSON rather than the complete
                 * <function=...> wrapper.
                 */
                var repairedJson =
                    JsonSanitizer.RepairJson(
                        argumentsJson,
                        _ignoreParameters) ?? "";

                /*
                 * Ensure the repaired value is actually valid JSON.
                 *
                 * Function arguments should normally be a JSON object,
                 * but validation here primarily protects the downstream
                 * function execution from malformed model output.
                 */
                using var document = JsonDocument.Parse(repairedJson);

                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    _logger.LogWarning(
                        "Ignoring Llama 3.1 function call {FunctionName} because parameters are not a JSON object: {Parameters}",
                        functionName,
                        repairedJson);

                    continue;
                }

                /*
                 * Use the normalized JSON emitted by JsonDocument so the
                 * duplicate check is not affected by insignificant
                 * whitespace differences.
                 */
                var sanitizedJson =
                    document.RootElement.GetRawText();

                var key = $"{functionName}\n{sanitizedJson}";

                if (seen.Add(key))
                {
                    functionCalls.Add(
                        (sanitizedJson, functionName));
                }

                _logger.LogDebug(
                    "Parsed Llama 3.1 function call: {FunctionName}, JSON: {SanitizedJson}",
                    functionName,
                    sanitizedJson);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Failed to parse Llama 3.1 function call {FunctionName} with arguments: {Arguments}",
                    functionCall.functionName,
                    functionCall.argumentsJson);
            }
        }

        return functionCalls;
    }

    private static string NormalizeLlama31Output(string input)
    {
        /*
         * Function-tag custom calls normally finish with <|eot_id|>.
         *
         * Remove model control tokens because they are not part of the
         * function name or parameter JSON.
         *
         * <|eom_id|> is tolerated as well in case a particular model or
         * quantization emits it.
         */
        input = input.Replace(EotToken, "");
        input = input.Replace(EomToken, "");

        return input.Trim();
    }

    private static IEnumerable<(string functionName, string argumentsJson)>
        ExtractFunctionCalls(string input)
    {
        /*
         * Expected format:
         *
         * <function=run_nmap>{"target":"example.com"}</function>
         *
         * Function names are deliberately restricted to the normal set of
         * characters used by function/tool names. This prevents accidental
         * matching of unrelated model output.
         *
         * Singleline allows pretty-printed JSON between the tags even though
         * the prompt asks the model to place the entire call on one line.
         */
        var pattern =
            @"<function\s*=\s*(?<name>[A-Za-z0-9_.:-]+)\s*>\s*(?<arguments>.*?)\s*</function>";

        var matches = Regex.Matches(
            input,
            pattern,
            RegexOptions.Singleline | RegexOptions.IgnoreCase);

        foreach (Match match in matches)
        {
            if (!match.Success)
            {
                continue;
            }

            var functionName =
                match.Groups["name"].Value;

            var argumentsJson =
                match.Groups["arguments"].Value;

            if (string.IsNullOrWhiteSpace(functionName))
            {
                continue;
            }

            yield return (
                functionName,
                argumentsJson);
        }
    }
}

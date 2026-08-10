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
    private const string PythonTag = "<|python_tag|>";
    private const string EomToken = "<|eom_id|>";
    private const string EotToken = "<|eot_id|>";

    public TokenBroadcasterLlama_3_1(
        ILLMResponseProcessor responseProcessor,
        ILogger logger,
        bool xmlFunctionParsing,
        HashSet<string> ignoreParameters)
        : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
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

        /*
         * Preferred Llama 3.1 tool output:
         *
         * <|python_tag|>{"name":"function_name","parameters":{...}}<|eom_id|>
         *
         * Strip the Llama control tokens before parsing the JSON.
         *
         * We deliberately do not require <|python_tag|> to be present because
         * the model may occasionally emit the bare JSON function call despite
         * being prompted to use the native Llama 3.1 wrapper.
         */
        input = NormalizeLlama31ToolOutput(input);

        /*
         * Llama 3.1 may occasionally produce the more native-looking form:
         *
         * {
         *   "type": "function",
         *   "name": "...",
         *   "parameters": {...}
         * }
         *
         * Our application does not need the "type" property, so remove it when
         * it occurs at the beginning of a top-level function call.
         */
        input = Regex.Replace(
            input,
            @"^\s*{\s*""type""\s*:\s*""function""\s*,?\s*",
            "{");

        // Normalize pretty-printed JSON so "{" immediately precedes "name".
        input = Regex.Replace(
            input,
            @"{\s*(?=""name"")",
            "{");

        foreach (var candidate in ExtractJsonObjects(input))
        {
            if (!LooksLikeFunctionCallCandidate(candidate))
            {
                continue;
            }

            try
            {
                var repairedJson = JsonSanitizer.RepairJson(
                    candidate,
                    _ignoreParameters);

                using var document = JsonDocument.Parse(repairedJson);
                var root = document.RootElement;

                if (!TryExtractFunctionCall(
                    root,
                    out var functionName,
                    out var parametersJson))
                {
                    continue;
                }

                var sanitizedJson =
                    JsonSanitizer.RepairJson(
                        parametersJson,
                        _ignoreParameters) ?? "";

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
                    "Failed to parse or repair Llama 3.1 JSON block: {JsonBlock}",
                    candidate);
            }
        }

        return functionCalls;
    }

    private static string NormalizeLlama31ToolOutput(string input)
    {
        /*
         * Remove the tool-call opening marker.
         *
         * Do this globally rather than only at position zero because some
         * models may emit whitespace or other harmless text before it.
         */
        input = input.Replace(PythonTag, "");

        /*
         * <|eom_id|> means the assistant has yielded control to the tool
         * execution environment. It is not part of the JSON payload.
         */
        input = input.Replace(EomToken, "");

        /*
         * Also tolerate <|eot_id|>. It is technically not the preferred
         * terminator for an intermediate Llama 3.1 tool invocation, but some
         * models/quantisations may produce it anyway.
         */
        input = input.Replace(EotToken, "");

        return input.Trim();
    }

    private static bool LooksLikeFunctionCallCandidate(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        return json.Contains("\"name\"")
               && (json.Contains("\"parameters\"")
                   || json.Contains("\"arguments\"")
                   || json.Contains("\"function\""));
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

                    yield return input.Substring(
                        start,
                        i - start + 1);
                }
            }
        }
    }

    private static bool TryExtractFunctionCall(
        JsonElement element,
        out string functionName,
        out string parametersJson)
    {
        functionName = "";
        parametersJson = "";

        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        return TryExtractFromObject(
            element,
            out functionName,
            out parametersJson);
    }

    private static bool TryExtractFromObject(
        JsonElement element,
        out string functionName,
        out string parametersJson)
    {
        functionName = "";
        parametersJson = "";

        /*
         * Your application's preferred format:
         *
         * {
         *   "name": "function_name",
         *   "parameters": {...}
         * }
         *
         * Also accept "arguments" because models sometimes use the
         * OpenAI-style naming despite the prompt.
         */
        if (element.TryGetProperty("name", out var nameElement)
            && nameElement.ValueKind == JsonValueKind.String)
        {
            if (element.TryGetProperty(
                    "parameters",
                    out var parametersElement)
                || element.TryGetProperty(
                    "arguments",
                    out parametersElement))
            {
                functionName =
                    nameElement.GetString() ?? "";

                parametersJson =
                    ExtractParametersJson(parametersElement);

                return !string.IsNullOrEmpty(functionName);
            }
        }

        /*
         * Also tolerate:
         *
         * {
         *   "function": {
         *      "name": "...",
         *      "arguments": {...}
         *   }
         * }
         */
        if (element.TryGetProperty(
                "function",
                out var functionElement)
            && functionElement.ValueKind == JsonValueKind.Object)
        {
            return TryExtractFromObject(
                functionElement,
                out functionName,
                out parametersJson);
        }

        return false;
    }

    private static string ExtractParametersJson(
        JsonElement parametersElement)
    {
        /*
         * Some models serialize arguments twice:
         *
         * "arguments": "{\"target\":\"example.com\"}"
         *
         * while others correctly return:
         *
         * "arguments": {"target":"example.com"}
         *
         * Support both.
         */
        if (parametersElement.ValueKind == JsonValueKind.String)
        {
            return parametersElement.GetString() ?? "";
        }

        return parametersElement.GetRawText();
    }
}

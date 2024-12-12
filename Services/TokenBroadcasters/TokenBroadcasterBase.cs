using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using System.Xml;
using Newtonsoft.Json;
using System.Text.RegularExpressions;


namespace NetworkMonitor.LLM.Services
{
    public static class XmlToJsonConverter
    {
        public static string ConvertXmlToJson(string xml)
        {
            // Load the XML string into an XmlDocument
            var doc = new XmlDocument();
            doc.LoadXml(xml);

            // Convert XML to JSON and return it
            string json = JsonConvert.SerializeXmlNode(doc, Newtonsoft.Json.Formatting.None, true);
            return json;
        }
    }
    public abstract class TokenBroadcasterBase : ITokenBroadcaster
    {
        protected readonly ILLMResponseProcessor _responseProcessor;
        protected readonly ILogger _logger;
        protected CancellationTokenSource _cancellationTokenSource;
        protected bool _isPrimaryLlm;
        protected bool _isFuncCalled;
        StringBuilder? _assistantMessage = null;
        protected bool _xmlFunctionParsing = false;

        public StringBuilder AssistantMessage { get => _assistantMessage; }

        protected TokenBroadcasterBase(ILLMResponseProcessor responseProcessor, ILogger logger)
        {
            _responseProcessor = responseProcessor;
            _logger = logger;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task ReInit(string sessionId)
        {
            _logger.LogInformation("Cancel due to ReInit called");
            await _cancellationTokenSource.CancelAsync();
        }

        public abstract Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, int countEOT, bool sendOutput = true);

        protected int CountOccurrences(string source, string substring)
        {
            int count = 0, index = 0;
            while ((index = source.IndexOf(substring, index)) != -1)
            {
                count++;
                index += substring.Length;
            }
            return count;
        }

        protected bool IsTokenComplete(StringBuilder tokenBuilder)
        {
            return tokenBuilder.Length > 0 && char.IsWhiteSpace(tokenBuilder[^1]);
        }

        protected virtual async Task ProcessLine(string line, LLMServiceObj serviceObj)
        {
            // Default implementation of ProcessLine. Can be overridden by subclasses.
            var responseServiceObj = new LLMServiceObj(serviceObj);
            if (serviceObj.IsFunctionCallResponse)
            {
                responseServiceObj.LlmMessage = "</functioncall-complete>";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }
            List<(string json, string functionName)> functionCalls = new();
            if (_xmlFunctionParsing) functionCalls = ParseInputForXml(line);
            else functionCalls = ParseInputForJson(line);
            if (functionCalls != null && functionCalls.Count > 0) _assistantMessage = new StringBuilder($"I have called the following functions : ");

            foreach (var (jsonArguments, functionName) in functionCalls)
            {
                if (!string.IsNullOrWhiteSpace(jsonArguments))
                {
                    _assistantMessage.Append($" Name {functionName} Arguments {jsonArguments} : ");

                    _logger.LogInformation($"ProcessLLMOutput(call_func) -> {jsonArguments}");
                    responseServiceObj.LlmMessage = "</functioncall>";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    responseServiceObj.LlmMessage = "";
                    responseServiceObj.IsFunctionCall = true;
                    responseServiceObj.IsFunctionCallResponse = false;
                    responseServiceObj.JsonFunction = jsonArguments;
                    responseServiceObj.FunctionName = functionName;
                    responseServiceObj.IsProcessed = false;
                    await _responseProcessor.ProcessFunctionCall(responseServiceObj);
                    _isFuncCalled = true;

                }
            }
            if (functionCalls != null && functionCalls.Count > 0) _assistantMessage.Append($" using message_id {serviceObj.MessageID} . Please wait it may take some time to complete.");

            responseServiceObj.LlmMessage = "<end-of-line>";
            if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
        }




      protected virtual List<(string json, string functionName)> ParseInputForXml(string input)
{
    var functionCalls = new List<(string json, string functionName)>();

    // Define a regex pattern to match XML function calls in the mixed input
    var pattern = @"<function_call\s+name=""(?<name>[^""]+)"">.*?<parameters>(?<parameters>.*?)</parameters>.*?</function_call>";

    // Find all matches (XML blocks)
    var matches = Regex.Matches(input, pattern, RegexOptions.Singleline);

    foreach (Match match in matches)
    {
        var functionName = match.Groups["name"].Value;
        var parameters = match.Groups["parameters"].Value;

        // Handle CDATA content by fixing incomplete CDATA sections
        string cleanedParameters = CleanCdata(parameters);

        // Load the cleaned parameters XML into an XmlDocument
        var doc = new XmlDocument();
        doc.LoadXml($"<parameters>{cleanedParameters}</parameters>");

        // Extract the <parameters> node and convert it to JSON
        string jsonParameters = JsonConvert.SerializeXmlNode(doc.DocumentElement, Newtonsoft.Json.Formatting.None, true);

        // Add the function name and the converted JSON parameters to the result
        functionCalls.Add((jsonParameters, functionName));
    }

    return functionCalls;
}

// Clean the CDATA content by ensuring proper CDATA formatting
private string CleanCdata(string parameters)
{
    parameters=parameters.Trim();
    // Check if the parameters contain a CDATA section
    if (parameters.Contains("<![CDATA["))
    {
        // If there's an opening <![CDATA[ but no closing ]]> tag, add it
        if (!parameters.Contains("]]>"))
        {
            parameters = parameters + "]]>";  // Add the closing CDATA tag
        }
    }
    // Add CDATA if its missing
     if (!parameters.StartsWith("<![CDATA["))
    { 
            parameters = "<![CDATA["+parameters + "]]>";      
    }

    return parameters;
}

        protected virtual List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var functionsCalls = new List<(string json, string functionName)>();
            if (input.Contains("FUNCTION RESPONSE:"))
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
}

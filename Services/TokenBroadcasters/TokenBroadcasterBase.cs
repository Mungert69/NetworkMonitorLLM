using System;
using System.IO;
using System.Text;
using System.Linq;
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
    public interface ITokenBroadcaster
    {
        void Init(LLMConfig config);
        void ReInit(string sessionId);
        Task SetUp(LLMServiceObj serviceObj, bool sendOutput, int llmLoad);
        StringBuilder? AssistantMessage { get; set; }
        StringBuilder? SystemMessage { get; set; }
        Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput);
        List<(string json, string functionName)> ParseInputForJson(string input);
        List<(string json, string functionName)> ParseInputForXml(string input);
        string ResponseContent { get; }
        bool IsAddAssistant { get; set; }
        bool UseHttpProcess { get; set; }



    }

    public abstract class TokenBroadcasterBase : ITokenBroadcaster, IDisposable
    {
        protected readonly ILLMResponseProcessor _responseProcessor;
        protected readonly ILogger _logger;
        protected CancellationTokenSource _cancellationTokenSource;
        protected bool _isPrimaryLlm;
        protected bool _isSystemLlm;
        protected bool _isFuncCalled;
        StringBuilder? _assistantMessage = null;
        StringBuilder? _systemMessage = null;
        protected bool _xmlFunctionParsing = false;
        private bool _disposed = false; // To detect redundant calls to Dispose
        protected string _userReplace = "";
        protected string _functionReplace = "";
        protected string _assistantHeader = "";
        protected int _stopAfter = 2;
        protected List<string> _endTokens = new List<string>();
        protected LLMConfig _config;
        protected HashSet<string> _ignoreParameters;
        private bool _isAddAssistant = false;
        private bool _useHttpProcess = false;
        private StringBuilder _responseContentBuilder = new StringBuilder();
        public string ResponseContent => _responseContentBuilder.ToString();
        private readonly Queue<(string? FunctionName, string? ArgumentsJson)> _recentFunctionCalls = new Queue<(string?, string?)>();
        private const int MaxRecentFunctionCalls = 5; // Adjust as needed
        public StringBuilder? SystemMessage { get => _systemMessage; set => _systemMessage = value; }
        public StringBuilder? AssistantMessage { get => _assistantMessage; set => _assistantMessage = value; }
        public bool IsAddAssistant { get => _isAddAssistant; set => _isAddAssistant = value; }
        public bool UseHttpProcess { get => _useHttpProcess; set => _useHttpProcess = value; }

        protected TokenBroadcasterBase(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing, HashSet<string> ignoreParameters)
        {
            _responseProcessor = responseProcessor;
            _xmlFunctionParsing = xmlFunctionParsing;
            _ignoreParameters = ignoreParameters;
            _logger = logger;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public void ReInit(string sessionId)
        {
            _logger.LogInformation("Cancel due to ReInit called");
            try
            {
                _cancellationTokenSource.Cancel();
            }
            catch (ObjectDisposedException ex)
            {
                _logger.LogWarning($"CancellationTokenSource was already disposed: {ex.Message}");
            }

            _cancellationTokenSource.Dispose();
            _cancellationTokenSource = new CancellationTokenSource();
        }

        protected virtual string RemoveThinking(string input, string thinkTag = "think")
        {
            // Escape the tag to handle special regex characters if present
            string escapedTag = Regex.Escape(thinkTag);

            // Build the regex pattern dynamically
            string pattern = $@"<{escapedTag}>.*?</{escapedTag}>";

            // Perform the replacement
            string result = Regex.Replace(input, pattern, "", RegexOptions.Singleline);

            return result;
        }


        public async Task SendLLMPrimaryChunk(LLMServiceObj serviceObj, string chunk)
        {
            var chunkServiceObj = new LLMServiceObj(serviceObj)
            {
                LlmMessage = chunk
            };
            if (_isPrimaryLlm)
                await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
        }

        public async Task SendLLMPrimary(LLMServiceObj serviceObj)
        {

            if (_isPrimaryLlm)
                await _responseProcessor.ProcessLLMOutput(serviceObj);
        }
        public async Task SendLLM(LLMServiceObj serviceObj)
        {
            await _responseProcessor.ProcessLLMOutput(serviceObj);
        }
        public async Task SendFunctionCall(LLMServiceObj serviceObj)
        {
            await _responseProcessor.ProcessFunctionCall(serviceObj);
        }

        public void Init(LLMConfig config)
        {
            _userReplace = config.UserReplace;
            _functionReplace = config.FunctionReplace;
            _assistantHeader = config.AssistantHeader;
            _endTokens = new List<string>();
            _endTokens.Add(config.EOTToken);
            if (!string.IsNullOrEmpty(config.EOMToken)) _endTokens.Add(config.EOMToken);



        }


        public async Task SetUp(LLMServiceObj serviceObj, bool sendOutput, int llmLoad)
        {
            _isPrimaryLlm = serviceObj.IsPrimaryLlm;
            _isSystemLlm = serviceObj.IsSystemLlm;
            _logger.LogInformation($"IsSystemLlm {_isSystemLlm} IsPrimaryLlm {_isPrimaryLlm}");
            _responseProcessor.SendOutput = sendOutput;
            _isFuncCalled = false;

            await SendLLMPrimaryChunk(serviceObj, "</llm-busy>");
            if (llmLoad > 0)
            {
                await SendLLMPrimaryChunk(serviceObj, $"<load-count>{llmLoad}</load-count>");
                _logger.LogInformation($"<load-count>{llmLoad}</load-count>");
            }

        }

        public async Task SendHeader(LLMServiceObj serviceObj, string userInput)
        {
            var chunkServiceObj = new LLMServiceObj(serviceObj);
            if (_isAddAssistant)
            {
                chunkServiceObj.LlmMessage = "<Assistant:>";
                await SendLLMPrimary(chunkServiceObj);
                return;
            }
            if (serviceObj.IsFunctionCallResponse)
            {
                userInput = userInput.Replace(_functionReplace, "<Function Response:> ");
                userInput = StripExtraFuncHeader(userInput);
                userInput = userInput.Replace("\n", "");
                chunkServiceObj.LlmMessage = userInput;
            }
            else chunkServiceObj.LlmMessage = userInput.Replace(_userReplace, "<User:> ") + "\n";
            await SendLLMPrimary(chunkServiceObj);


        }
        protected virtual string StripExtraFuncHeader(string input)
        {
            return input;
        }

        protected string ConvertToContent(string line)
        {
            var jsonContent = line["data:".Length..].Trim();
            if (jsonContent.Contains("data: [DONE]")) return "<|DONE|>";

            try
            {
                var partialResponse = JsonConvert.DeserializeObject<StreamingChatCompletionChunk>(jsonContent);
                var contentChunk = partialResponse?.Choices?.FirstOrDefault()?.Delta?.Content ?? "";
                return contentChunk;
            }
            catch
            {
                return "<|Error|>";
            }
        }

        public virtual async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput)
        {
            _logger.LogWarning(" Start BroadcastAsyc() ");
            await SendHeader(serviceObj, userInput);


            var lineBuilder = new StringBuilder();
            var llmOutFull = new StringBuilder();
            _responseContentBuilder = new StringBuilder();
            int stopCount = 0;

            try
            {
                while (!_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    byte[] buffer = new byte[1024];
                    int charRead;
                    if (_useHttpProcess) charRead = await process.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
                    else charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
                    string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
                    if (_useHttpProcess)
                    {
                        textChunk = ConvertToContent(textChunk);
                        if (textChunk == "<|DONE|>")
                        {
                            _cancellationTokenSource.Cancel();
                            break;
                        }

                    }
                    llmOutFull.Append(textChunk);
                    _responseContentBuilder.Append(textChunk);
                    await SendLLMPrimaryChunk(serviceObj, textChunk);
                    string llmOutStr = llmOutFull.ToString();
                    int eotIdCount = CountOccurrences(llmOutStr, _endTokens);

                    if (eotIdCount > stopCount)
                    {
                        stopCount++;
                        _logger.LogInformation($" Stop count {stopCount} output is {llmOutStr} ");

                    }
                    if (stopCount == _stopAfter)
                    {
                        await ProcessLine(llmOutStr, serviceObj);
                        _logger.LogInformation($" Cancel due to {stopCount} end tokens detected ");
                        _cancellationTokenSource.Cancel(); // Cancel after second <|eot_id|>}

                    }
                }

                if (!_isPrimaryLlm && !_isFuncCalled)
                {
                    string llmOutput = llmOutFull.ToString();
                    foreach (var token in _endTokens)
                    {
                        llmOutput = llmOutput.Replace(token, "");
                    }
                    llmOutput = llmOutput.Replace(_assistantHeader, "");

                    string extraMessage = "";
                    if (_isSystemLlm)
                    {
                        extraMessage += " From System LLM ";
                    }
                    else llmOutput = llmOutput.Replace("\n", " ");
                    var finalServiceObj = new LLMServiceObj(serviceObj, fs => fs.SetAsResponseComplete());
                    finalServiceObj.LlmMessage = llmOutput;
                    await _responseProcessor.ProcessLLMOutput(finalServiceObj);
                    _logger.LogInformation($" --> Sent redirected LLM Output {extraMessage}{finalServiceObj.LlmMessage}");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Read operation canceled due to CancellationToken.");
                await SendLLMPrimaryChunk(serviceObj, "\n");

            }
            finally
            {
                await SendLLMPrimaryChunk(serviceObj, "</llm-listening>");
            }
            _logger.LogInformation(" --> Finished LLM Interaction ");
        }

        protected int CountOccurrences(string source, List<string> substrings)
        {
            int count = 0;
            foreach (var substring in substrings)
            {
                int index = 0;
                while ((index = source.IndexOf(substring, index)) != -1)
                {
                    count++;
                    index += substring.Length;
                }
            }
            return count;
        }


        protected bool IsTokenComplete(StringBuilder tokenBuilder)
        {
            return tokenBuilder.Length > 0 && char.IsWhiteSpace(tokenBuilder[^1]);
        }

        protected async Task ProcessLine(string line, LLMServiceObj serviceObj)
        {
            var responseServiceObj = new LLMServiceObj(serviceObj);
            if (serviceObj.IsFunctionCallResponse) await SendLLMPrimaryChunk(responseServiceObj, "</functioncall-complete>");

            List<(string json, string functionName)> functionCalls = new();
            if (_xmlFunctionParsing) functionCalls = ParseInputForXml(line);
            else functionCalls = ParseInputForJson(line);

            bool makeAssistantMessage = false;
            // if (functionCalls != null && functionCalls.Count > 0 && !functionCalls.Any(f => f.functionName == "are_functions_running")) makeAssistantMessage = true;

            if (makeAssistantMessage) _assistantMessage = new StringBuilder($"I have called the following functions ");

            foreach (var (jsonArguments, functionName) in functionCalls)
            {
                if (!string.IsNullOrWhiteSpace(jsonArguments))
                {
                    bool isDuplicate = _recentFunctionCalls.Any(f =>
                        f.FunctionName == functionName &&
                        f.ArgumentsJson == jsonArguments);
                    if (isDuplicate)
                    {
                        _logger.LogWarning($"Possible loop detected when calling function: {functionName}");

                        // Add a system message to guide the LLM out of the loop
                        if (SystemMessage == null) SystemMessage = new StringBuilder();
                        SystemMessage.AppendLine("You are possibly stuck in a loop. You need to stop calling functions and check what the user wants to do.");

                    }
                    _recentFunctionCalls.Enqueue((functionName, jsonArguments));

                    // Maintain queue size
                    while (_recentFunctionCalls.Count > MaxRecentFunctionCalls)
                    {
                        _recentFunctionCalls.Dequeue();
                    }

                    if (makeAssistantMessage && _assistantMessage != null) _assistantMessage.Append($" {functionName} ");

                    _logger.LogInformation($"ProcessLLMOutput(call_func) -> {jsonArguments}");
                    responseServiceObj.LlmMessage = "</functioncall>";
                    await SendLLMPrimary(responseServiceObj);
                    responseServiceObj.LlmMessage = "";
                    responseServiceObj.SetAsCall();
                    responseServiceObj.JsonFunction = jsonArguments;
                    responseServiceObj.FunctionName = functionName;
                    responseServiceObj.IsProcessed = false;
                    await SendFunctionCall(responseServiceObj);
                    _isFuncCalled = true;

                }
            }
            if (makeAssistantMessage && _assistantMessage != null) _assistantMessage.Append($" using message_id {serviceObj.MessageID}");

            responseServiceObj.LlmMessage = "<end-of-line>";
            await SendLLMPrimary(responseServiceObj);
        }




        public virtual List<(string json, string functionName)> ParseInputForXml(string input)
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

                // Load the cleaned parameters XML into an XmlDocument
                var doc = new XmlDocument();
                doc.LoadXml($"<parameters>{parameters}</parameters>");

                // Extract the <parameters> node and convert it to JSON
                string jsonParameters = JsonConvert.SerializeXmlNode(doc.DocumentElement, Newtonsoft.Json.Formatting.None, true);

                // Parse the JSON back into an object to manipulate the structure
                var parsedParameters = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonParameters) ?? new();
                // Check for "source_code" with a "#cdata-section" field
                if (parsedParameters.TryGetValue("source_code", out var sourceCodeNode) && sourceCodeNode is Newtonsoft.Json.Linq.JObject sourceCodeObj)
                {
                    // If "#cdata-section" exists, replace "source_code" with its value
                    if (sourceCodeObj.TryGetValue("#cdata-section", out var cdataSection))
                    {
                        parsedParameters["source_code"] = cdataSection.ToString();
                    }
                }
                // Add the `args_escaped` field we do this to indicate that it was create from non escapped code. So examples will not need to be escapped
                parsedParameters["args_escaped"] = false;

                // Convert the updated parameters back to JSON
                string adjustedJsonParameters = JsonConvert.SerializeObject(parsedParameters, Newtonsoft.Json.Formatting.None);

                // Add the function name and the adjusted JSON parameters to the result
                functionCalls.Add((adjustedJsonParameters, functionName));
            }

            return functionCalls;
        }


        public virtual List<(string json, string functionName)> ParseInputForJson(string input)
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
                functionsCalls.Add((JsonSanitizer.RepairJson(newLine, _ignoreParameters), ""));
                return functionsCalls;
            }
            else
            {
                functionsCalls.Add((input, ""));
                return functionsCalls;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _cancellationTokenSource?.Dispose();
            }

            // Set fields to null
            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        ~TokenBroadcasterBase()
        {
            Dispose(disposing: false);
        }
    }
}

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
using NetworkMonitor.LLM.Services.Objects;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Linq;
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterFunc_2_4 : ITokenBroadcaster
{
    private readonly ILLMResponseProcessor _responseProcessor;
    private readonly ILogger _logger;
    private bool _isPrimaryLlm;
    private bool _isFuncCalled;
    public event Func<object, string, Task> LineReceived;
    private CancellationTokenSource _cancellationTokenSource;
    public TokenBroadcasterFunc_2_4(ILLMResponseProcessor responseProcessor, ILogger logger)
    {
        _responseProcessor = responseProcessor;
        _logger = logger;
        _cancellationTokenSource = new CancellationTokenSource();
    }
    public async Task ReInit(string sessionId)
    {
        _logger.LogInformation(" Cancel due to ReInit called ");
        await _cancellationTokenSource.CancelAsync();
    }
    public async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, bool sendOutput)
    {
        _logger.LogWarning($" Start BroadcastAsync() DestinationLlm {serviceObj.DestinationLlm} SourceLlm {serviceObj.SourceLlm} ");
        _responseProcessor.SendOutput = sendOutput;
        var cancellationToken = _cancellationTokenSource.Token;
        var llmOutFull = new StringBuilder();
        var tokenBuilder = new StringBuilder();
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        _isFuncCalled = false;
        var forwardSegments = new List<MessageSegment>();

        bool isStopEncountered = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            byte[] buffer = new byte[50];
            int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
            string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
            var chunkServiceObj = new LLMServiceObj(serviceObj);
            chunkServiceObj.LlmMessage = textChunk;
            if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
            llmOutFull.Append(textChunk);
            tokenBuilder.Append(textChunk);
            //Console.WriteLine(textChunk);
            if (IsTokenComplete(tokenBuilder))
            {
                string token = tokenBuilder.ToString();
                tokenBuilder.Clear();
                token = token.Replace("/\b", "");
                //Console.WriteLine(token);
            }
            //var (messageSegment, isWithinContent, isMessageSegmentComplete) = ParseLLMOutput(llmOutFull.ToString());
            var (messageSegments, isMessageSegmentsComplete) = ParseLLMOutputMulti(llmOutFull.ToString());
            if (isMessageSegmentsComplete && messageSegments != null && messageSegments.Count > 0)
            {
                foreach (var messageSegment in messageSegments)
                {

                    LLMServiceObj responseServiceObj = new LLMServiceObj(serviceObj);
                    if (serviceObj.IsFunctionCallResponse)
                    {
                        responseServiceObj.LlmMessage = "</functioncall-complete>";
                        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    }
                    await ProcessMessageSegment(messageSegment, serviceObj.SessionId, userInput, serviceObj.SourceLlm, serviceObj.DestinationLlm);
                }
                if (!_isPrimaryLlm) forwardSegments = messageSegments;
                _cancellationTokenSource.Cancel();
                isStopEncountered = true;
            }
            if (isStopEncountered)
                break;
        }
        if (!_isPrimaryLlm && !_isFuncCalled)
        {
            string llmOutput = "Message to sent from Remote LLM format corrupt.";
            //string test = llmOutFull.ToString();
            try
            {
                if (forwardSegments.Count > 0)
                {
                    var assistantSegment = forwardSegments.Where(a => a.From.Contains("assistant")).FirstOrDefault();
                    if (assistantSegment != null) llmOutput = assistantSegment.Content.Replace("\n", "").Replace("<|stop|>", "");
                }
            }
            catch { }

            var finalServiceObj = new LLMServiceObj(serviceObj);
            finalServiceObj.LlmMessage = llmOutput;
            finalServiceObj.IsFunctionCall = false;
            finalServiceObj.IsFunctionCallResponse = true;
            await _responseProcessor.ProcessLLMOutput(finalServiceObj);
            _logger.LogInformation($" --> Sent redirected LLM Output {finalServiceObj.LlmMessage}");
        }

        _logger.LogInformation(" --> LLM Output --> " + llmOutFull.ToString());
        _logger.LogInformation(" --> Finished LLM Interaction ");
    }

    private bool IsTokenComplete(StringBuilder tokenBuilder)
    {
        string token = tokenBuilder.ToString();
        if (token.Length > 0 && char.IsWhiteSpace(token[^1])) return true;
        // Check for whitespace characters that indicate token boundaries
        return false;
    }
    public static (MessageSegment, bool, bool) ParseLLMOutput(string output)
    {
        var regex = new Regex(@"<\|(?<tag>\w+)\|>(?<value>.+?(?=<\|))");
        string outputClean = output.Replace("\n", ""); // Remove newlines
        string from = "";
        string recipient = "";
        string content = "";
        bool isWithinContent = false;
        bool isMessageSegmentComplete = false;
        if (output.Contains("<|stop|>"))
        {
            isMessageSegmentComplete = true;
        }
        var matches = regex.Matches(outputClean);
        foreach (Match match in matches)
        {
            var tag = match.Groups["tag"].Value;
            string value = match.Groups["value"].Value;
            switch (tag)
            {
                case "from":
                    from = value.Trim();
                    break;
                case "recipient":
                    recipient = value.Trim();
                    break;
                case "content":
                    isWithinContent = true;
                    content = value.Trim();
                    break;
            }
        }
        var messageSegment = new MessageSegment()
        {
            From = from,
            Recipient = recipient,
            Content = content
        };
        return (messageSegment, isWithinContent, isMessageSegmentComplete);
    }

    public static (List<MessageSegment>, bool) ParseLLMOutputMulti(string output)
    {
        bool isMessageSegmentsComplete = false;
        var regex = new Regex(@"<\|(?<tag>\w+)\|>(?<value>.+?(?=<\|)|.+?(?=\\n\|<\\|))");
        string outputClean = output.Replace("\n", ""); // Remove newlines
        var messageSegments = new List<MessageSegment>();
        var matches = regex.Matches(outputClean);
        if (output.Contains("<|stop|>"))
        {
            isMessageSegmentsComplete = true;
            MessageSegment currentSegment = null;

            foreach (Match match in matches)
            {
                var tag = match.Groups["tag"].Value;
                string value = match.Groups["value"].Value;
                switch (tag)
                {
                    case "from":
                        if (currentSegment == null)
                        {
                            currentSegment = new MessageSegment();
                        }
                        currentSegment.From = value.Trim();
                        break;
                    case "recipient":
                        if (currentSegment == null)
                        {
                            currentSegment = new MessageSegment();
                        }
                        currentSegment.Recipient = value.Trim();
                        break;
                    case "content":
                        if (currentSegment == null)
                        {
                            currentSegment = new MessageSegment();
                        }
                        currentSegment.Content = value.Trim();
                        messageSegments.Add(currentSegment);
                        currentSegment = null; // Reset for the next segment
                        break;
                }
            }
        }

        return (messageSegments, isMessageSegmentsComplete);
    }

    private static string ReadUntil(string input, int startIndex, char stopChar)
    {
        var sb = new System.Text.StringBuilder();
        while (startIndex < input.Length && input[startIndex] != stopChar)
        {
            sb.Append(input[startIndex]);
            startIndex++;
        }
        return sb.ToString();
    }
    private async Task ProcessMessageSegment(MessageSegment messageSegment, string sessionId, string userInput, string sourceLlm, string destinationLlm)
    {
        LLMServiceObj responseServiceObj = new LLMServiceObj() { SessionId = sessionId, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
        string line = messageSegment.Content;

        if (messageSegment.From == "assistant" && messageSegment.Recipient != "all")
        {
            var (isJson, jsonLine) = ParseInputForJson(line);
            //string cleanLine = line;
            if (isJson)
            {
                var jsonFunction = "{\"name\" : \"" + messageSegment.Recipient + "\" , \"parameters\" : " + jsonLine + "}";
                _logger.LogInformation($" ProcessLLMOutput(call_func) -> {jsonLine}");
                responseServiceObj = new LLMServiceObj() { SessionId = sessionId, UserInput = userInput, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
                responseServiceObj.LlmMessage = "</functioncall>";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                else
                {
                    /*var forwardFuncServiceObj = new LLMServiceObj(responseServiceObj);
                    forwardFuncServiceObj.LlmMessage = $"Please wait calling function with parameters {jsonLine}. Be patient this may take some time";
                    forwardFuncServiceObj.IsFunctionCall = false;
                    forwardFuncServiceObj.IsFunctionCallResponse = true;
                    forwardFuncServiceObj.FunctionName = messageSegment.Recipient;
                    await _responseProcessor.ProcessLLMOutput(forwardFuncServiceObj);
                    _logger.LogInformation($" --> Sent redirected LLM Function Output {forwardFuncServiceObj.LlmMessage}");
                    */
                }
                responseServiceObj.LlmMessage = "";
                responseServiceObj.IsFunctionCall = true;
                responseServiceObj.JsonFunction = jsonFunction;
                responseServiceObj.FunctionName = messageSegment.Recipient;
                //responseServiceObj.JsonFunction = CallFuncJson(cleanLine);
                await _responseProcessor.ProcessFunctionCall(responseServiceObj);
                _isFuncCalled = true;
            }
        }
        responseServiceObj.LlmMessage = "<end-of-line>";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
    }
    public string CallFuncJson(string input)
    {
        string callFuncJson = "";
        string funcName = "addHost";
        int startIndex = input.IndexOf('{');
        int lastClosingBraceIndex = input.LastIndexOf('}');
        string json = "";
        if (startIndex != -1)
        {
            json = input.Substring(startIndex, lastClosingBraceIndex + 1);
        }
        callFuncJson = "{ \"name\" : \"" + funcName + "\" \"arguments\" : \"" + json + "\"}";
        return callFuncJson;
    }
    private (bool, string) ParseInputForJson(string input)
    {
        string newLine = string.Empty;
        // bool foundStart = false;
        bool foundEnd = false;
        int startIndex = input.IndexOf('{');
        // If '{' is not found or is too far into the input, return the original input
        if (startIndex == -1)
        {
            return (false, input);
        }
        newLine = input.Substring(startIndex);
        int lastClosingBraceIndex = newLine.LastIndexOf('}');
        if (lastClosingBraceIndex != -1)
        {
            newLine = newLine.Substring(0, lastClosingBraceIndex + 1);
            foundEnd = true;
        }
        if (foundEnd) return (true, JsonSanitizer.SanitizeJson(newLine));
        else return (false, input);
    }
}
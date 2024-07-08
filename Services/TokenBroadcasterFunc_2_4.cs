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
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterFunc_2_4 : ITokenBroadcaster
{
    private readonly ILLMResponseProcessor _responseProcessor;
    private readonly ILogger _logger;
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
    public async Task BroadcastAsync(ProcessWrapper process, string sessionId, string userInput, bool isFunctionCallResponse, bool sendOutput)
    {
        _logger.LogWarning(" Start BroadcastAsync() ");
        _responseProcessor.SendOutput = sendOutput;
        var cancellationToken = _cancellationTokenSource.Token;
        var llmOutFull = new StringBuilder();
        var tokenBuilder = new StringBuilder();

        bool isStopEncountered = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            byte[] buffer = new byte[1];
            int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
            string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
            var serviceObj = new LLMServiceObj { SessionId = sessionId, LlmMessage = textChunk };
            await _responseProcessor.ProcessLLMOutput(serviceObj);
            llmOutFull.Append(textChunk);
            tokenBuilder.Append(textChunk);
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

                    LLMServiceObj responseServiceObj = new LLMServiceObj { SessionId = sessionId };
                    if (isFunctionCallResponse)
                    {
                        responseServiceObj.LlmMessage = "</functioncall-complete>";
                        await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    }
                    await ProcessMessageSegment(messageSegment, sessionId, userInput);



                }
                _cancellationTokenSource.Cancel();
                isStopEncountered = true;
            }
            if (isStopEncountered)
                break;
        }
        //_logger.LogInformation(" --> LLM Output --> "+llmOutFull.ToString());
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
        string? from = null;
        string? recipient = null;
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
        if (from == null) from = "assistant";
        if (recipient == null) recipient = "all";
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
                        if (currentSegment.From == null) currentSegment.From = "assistant";
                        if (currentSegment.Recipient == null) currentSegment.Recipient = "all";
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
    private async Task ProcessMessageSegment(MessageSegment messageSegment, string sessionId, string userInput)
    {
        LLMServiceObj responseServiceObj = new LLMServiceObj() { SessionId = sessionId };
        string line = messageSegment.Content;

        if (messageSegment.From == "assistant" && messageSegment.Recipient != "all")
        {
            var (isJson, jsonLine) = ParseInputForJson(line);
            //string cleanLine = line;
            if (isJson)
            {
                var jsonFunction = "{\"name\" : \"" + messageSegment.Recipient + "\" , \"parameters\" : " + jsonLine + "}";
                _logger.LogInformation($" ProcessLLMOutput(call_func) -> {jsonLine}");
                responseServiceObj = new LLMServiceObj() { SessionId = sessionId, UserInput = userInput };
                responseServiceObj.LlmMessage = "</functioncall>";
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                responseServiceObj.LlmMessage = "";
                responseServiceObj.IsFunctionCall = true;
                responseServiceObj.JsonFunction = jsonFunction;
                responseServiceObj.FunctionName = messageSegment.Recipient;
                //responseServiceObj.JsonFunction = CallFuncJson(cleanLine);
                await _responseProcessor.ProcessFunctionCall(responseServiceObj);
            }
        }
        responseServiceObj.LlmMessage = "<end-of-line>";
        await _responseProcessor.ProcessLLMOutput(responseServiceObj);
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
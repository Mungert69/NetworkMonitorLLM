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
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcaster
{
    private readonly ILLMResponseProcessor _responseProcessor;
    private readonly ILogger _logger;
    public event Func<object, string, Task> LineReceived;
    private CancellationTokenSource _cancellationTokenSource;
    public TokenBroadcaster(ILLMResponseProcessor responseProcessor, ILogger logger)
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
    public async Task BroadcastAsync(ProcessWrapper process, string sessionId, string userInput, bool isFunctionCallResponse)
    {
        _logger.LogWarning(" Start BroadcastAsync() ");
        var cancellationToken = _cancellationTokenSource.Token;
        var llmOutFull = new StringBuilder();
        bool isStopEncountered = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            byte[] buffer = new byte[1];
            int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
            string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
            llmOutFull.Append(textChunk);
            //Console.WriteLine(llmOutFull.ToString());
            var (messageSegment, isWithinContent, isMessageSegmentComplete) = ParseLLMOutput(llmOutFull.ToString());
            if (messageSegment != null)
            {
                if (isWithinContent)
                {
                    var serviceObj = new LLMServiceObj { SessionId = sessionId, LlmMessage = textChunk };
                    await _responseProcessor.ProcessLLMOutput(serviceObj);
                }
                if (isMessageSegmentComplete)
                {
                    var serviceObj = new LLMServiceObj { SessionId = sessionId, LlmMessage = messageSegment.Content };
                    _logger.LogInformation($"sessionID={sessionId} line is =>{llmOutFull.ToString()}<=");
                    await ProcessMessageSegment(messageSegment, sessionId, userInput);
                    _logger.LogInformation(" Stop detected ");
                    _cancellationTokenSource.Cancel();
                    isStopEncountered = true;
                    break;
                }
            }
            if (isStopEncountered)
                break;
        }
        _logger.LogInformation(" --> Finished LLM Interaction ");
    }
    public static (MessageSegment, bool, bool) ParseLLMOutput(string output)
    {
        var regex = new Regex(@"<\|(?<tag>\w+)\|>(?<value>.+?(?=<\|))");
        string outputClean = output.Replace("\n", ""); // Remove newlines
        string from = null;
        string recipient = null;
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
        if (messageSegment.From != "user" && messageSegment.From != "assistant")
        {
            responseServiceObj.LlmMessage = "</functioncall-complete>";
            await _responseProcessor.ProcessLLMOutput(responseServiceObj);
        }
        else if (messageSegment.From == "assistant" && messageSegment.Recipient != "all")
        {
            var (isJson,jsonLine) = ParseInputForJson(line);
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
    private (bool,string) ParseInputForJson(string input)
    {
        string newLine = string.Empty;
        // bool foundStart = false;
        bool foundEnd = false;
        int startIndex = input.IndexOf('{');
        // If '{' is not found or is too far into the input, return the original input
        if (startIndex == -1)
        {
            return (false,input);
        }
        newLine = input.Substring(startIndex);
        int lastClosingBraceIndex = newLine.LastIndexOf('}');
        if (lastClosingBraceIndex != -1)
        {
            newLine = newLine.Substring(0, lastClosingBraceIndex + 1);
            foundEnd = true;
        }
        if (foundEnd) return (true,JsonSanitizer.SanitizeJson(newLine));
        else return (false,input);
    }
}
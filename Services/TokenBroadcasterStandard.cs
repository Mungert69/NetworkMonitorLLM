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
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterStandard : ITokenBroadcaster
{
    private readonly ILLMResponseProcessor _responseProcessor;
    private readonly ILogger _logger;
    public event Func<object, string, Task> LineReceived;
    private CancellationTokenSource _cancellationTokenSource;
    public TokenBroadcasterStandard(ILLMResponseProcessor responseProcessor, ILogger logger)
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
    public async Task BroadcastAsync(ProcessWrapper process, string sessionId, string userInput, bool isFunctionCallResponse, string sourceLlm, string destionationLlm,bool sendOutput=true)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        // trim up to / otherwise it won't match 
        string copyUserInput = userInput;
        int startIndex = userInput.IndexOf('/');
        // If '{' is not found or is too far into the input, return the original input
        if (startIndex != -1)
        {
            copyUserInput = userInput.Substring(0, startIndex);
        }
        var lineBuilder = new StringBuilder();
        var llmOutFull = new StringBuilder();
        var tokenBuilder = new StringBuilder();
        var cancellationToken = _cancellationTokenSource.Token;
        int newlineCounter = 0;
        bool isNewline = false;
        while (!cancellationToken.IsCancellationRequested)
        {

            byte[] buffer = new byte[1];
            int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
            string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
            lineBuilder.Append(textChunk);
            char currentChar = (char)charRead;
            tokenBuilder.Append(textChunk);
            if (IsTokenComplete(tokenBuilder))
            {
                string token = tokenBuilder.ToString();
                token = token.Replace("/\b", "");
                //Console.WriteLine(token);
                tokenBuilder.Clear();
                var serviceObj = new LLMServiceObj { SessionId = sessionId, LlmMessage = token, SourceLlm=sourceLlm, DestinationLlm= destionationLlm };
                await _responseProcessor.ProcessLLMOutput(serviceObj);
                if (isNewline && token == "> ")
                {
                    _logger.LogInformation($"sessionID={sessionId} line is =>{llmOutFull.ToString()}<=");
                    await ProcessLine(llmOutFull.ToString(), sessionId, userInput, isFunctionCallResponse, sourceLlm, destionationLlm);
                    //state = ResponseState.Completed;
                    _logger.LogInformation(" Cancel due to output end detected ");
                    _cancellationTokenSource.Cancel();
                }
                else isNewline = false;
            }
            if (IsLineComplete(lineBuilder))
            {
                string line = lineBuilder.ToString();
                if (line.Equals(userInput + "\n") || line.StartsWith(copyUserInput))
                {
                    var serviceObj = new LLMServiceObj { SessionId = sessionId, LlmMessage = "\nAssistant: ", SourceLlm=sourceLlm, DestinationLlm= destionationLlm };
                    await _responseProcessor.ProcessLLMOutput(serviceObj);
                }
                else
                {
                    llmOutFull.Append(line);
                    if (line == "\n") isNewline = true;
                }
                lineBuilder.Clear();
            }
        }
        _logger.LogInformation(" --> Finshed LLM Interaction ");
    }
    private bool IsLineComplete(StringBuilder lineBuilder)
    {
        return lineBuilder.ToString().EndsWith("\n");
    }
    private bool IsTokenComplete(StringBuilder tokenBuilder)
    {
        string token = tokenBuilder.ToString();
        if (token.Length > 0 && char.IsWhiteSpace(token[^1])) return true;
        // Check for whitespace characters that indicate token boundaries
        return false;
    }
    private async Task ProcessLine(string line, string sessionId, string userInput, bool isFunctionCallResponse,string sourceLlm, string destionationLlm)
    {
        LLMServiceObj responseServiceObj = new LLMServiceObj() { SessionId = sessionId , SourceLlm=sourceLlm, DestinationLlm= destionationLlm};
        if (isFunctionCallResponse)
        {
            responseServiceObj.LlmMessage = "</functioncall-complete>";
            await _responseProcessor.ProcessLLMOutput(responseServiceObj);
        }
        else
        {
            string jsonLine = ParseInputForJson(line);
            //string cleanLine = line;
            if (line != jsonLine)
            {
                _logger.LogInformation($" ProcessLLMOutput(call_func) -> {jsonLine}");
                responseServiceObj = new LLMServiceObj() { SessionId = sessionId, UserInput = userInput, SourceLlm=sourceLlm, DestinationLlm= destionationLlm };
                responseServiceObj.LlmMessage = "</functioncall>";
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                responseServiceObj.LlmMessage = "";
                responseServiceObj.IsFunctionCall = true;
                responseServiceObj.JsonFunction = jsonLine;
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
    private string ParseInputForJson(string input)
    {
        if (input.Contains("FUNCTION RESPONSE:")) return input;
        string newLine = string.Empty;
        // bool foundStart = false;
        bool foundEnd = false;
        int startIndex = input.IndexOf('{');
        // If '{' is not found or is too far into the input, return the original input
        if (startIndex == -1 )
        {
            return input;
        }
        newLine = input.Substring(startIndex);
        int lastClosingBraceIndex = newLine.LastIndexOf('}');
        if (lastClosingBraceIndex != -1)
        {
            newLine = newLine.Substring(0, lastClosingBraceIndex + 1);
            foundEnd = true;
        }
        if (foundEnd) return JsonSanitizer.SanitizeJson(newLine);
        else return input;
    }
}
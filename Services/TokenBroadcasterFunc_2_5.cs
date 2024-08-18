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
public class TokenBroadcasterFunc_2_5 : ITokenBroadcaster
{
    private readonly ILLMResponseProcessor _responseProcessor;
    private readonly ILogger _logger;
    public event Func<object, string, Task> LineReceived;
    private CancellationTokenSource _cancellationTokenSource;
    private bool _isPrimaryLlm;
    private bool _isFuncCalled;
    public TokenBroadcasterFunc_2_5(ILLMResponseProcessor responseProcessor, ILogger logger)
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
    public async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, bool sendOutput = true)
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
         _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        _isFuncCalled = false;
        var cancellationToken = _cancellationTokenSource.Token;
        int newlineCounter = 0;
        bool isNewline = false;
        while (!cancellationToken.IsCancellationRequested)
        {

            byte[] buffer = new byte[1];
            int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
            string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
            //lineBuilder.Append(textChunk);
            char currentChar = (char)charRead;
            tokenBuilder.Append(textChunk);
            llmOutFull.Append(textChunk);
            var chunkServiceObj = new LLMServiceObj(serviceObj);
            chunkServiceObj.LlmMessage = textChunk;
            await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
            if (IsTokenComplete(tokenBuilder))
            {
                string token = tokenBuilder.ToString();
                tokenBuilder.Clear();
                token = token.Replace("/\b", "");
            }
            if (llmOutFull.ToString().Contains("<|eot_id|>"))
            {
                _logger.LogInformation($"sessionID={serviceObj.SessionId} line is =>{llmOutFull.ToString()}<=");
                await ProcessLine(llmOutFull.ToString(), serviceObj.SessionId, userInput, serviceObj.IsFunctionCallResponse, serviceObj.SourceLlm, serviceObj.DestinationLlm);
                //state = ResponseState.Completed;
                _logger.LogInformation(" Cancel due to output end detected ");
                _cancellationTokenSource.Cancel();
            }
            /*if (IsLineComplete(lineBuilder))
            {
                string line = lineBuilder.ToString();
                if (line.Equals(userInput + "\n") || line.StartsWith(copyUserInput))
                {
                    var serviceObj = new LLMServiceObj { SessionId = sessionId, LlmMessage = "\nAssistant: " };
                    await _responseProcessor.ProcessLLMOutput(serviceObj);
                }
                else
                {
                    llmOutFull.Append(line);
                    if (line == "\n") isNewline = true;
                }
                lineBuilder.Clear();
            }*/
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
    private async Task ProcessLine(string line, string sessionId, string userInput, bool isFunctionCallResponse, string sourceLlm, string destinationLlm)
    {
        LLMServiceObj responseServiceObj = new LLMServiceObj() { SessionId = sessionId, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
        if (isFunctionCallResponse)
        {
            responseServiceObj.LlmMessage = "</functioncall-complete>";
            await _responseProcessor.ProcessLLMOutput(responseServiceObj);
        }
        else
        {
            (string jsonLine, string functionName) = ParseInputForJson(line);
            //string cleanLine = line;
            if (line != jsonLine)
            {
                _logger.LogInformation($" ProcessLLMOutput(call_func) -> {jsonLine}");
                responseServiceObj = new LLMServiceObj() { SessionId = sessionId, UserInput = userInput, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
                responseServiceObj.LlmMessage = "</functioncall>";
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                responseServiceObj.LlmMessage = "";
                responseServiceObj.IsFunctionCall = true;
                responseServiceObj.JsonFunction = jsonLine;
                if (!String.IsNullOrEmpty(functionName))
                {
                    responseServiceObj.FunctionName = functionName;
                }
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
    private static (string json, string functionName) ParseInputForJson(string input)
    {
        string specialToken = "<|reserved_special_token_249|>";
        string output = input;

        // Check if the input contains the special token
        int tokenIndex = input.IndexOf(specialToken);
        if (tokenIndex == -1)
        {
            return (output, "");
        }

        // Extract the string after the special token
        string postTokenString = input.Substring(tokenIndex + specialToken.Length);

        // Find the start index of the JSON content
        int jsonStartIndex = postTokenString.IndexOf('{');
        if (jsonStartIndex == -1)
        {
            return (output, "");
        }

        // Extract the JSON content
        string jsonContent = postTokenString.Substring(jsonStartIndex);

        // Extract the function name
        string functionNamePart = postTokenString.Substring(0, jsonStartIndex);
        string functionName = functionNamePart.Replace("\n", "").Trim();

        // Find the end of the JSON content
        int jsonEndIndex = jsonContent.LastIndexOf('}');
        if (jsonEndIndex != -1)
        {
            jsonContent = jsonContent.Substring(0, jsonEndIndex + 1);
        }
        else
        {
            return (output, "");
        }

        return (JsonSanitizer.SanitizeJson(jsonContent), functionName);
    }
}
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
public class TokenBroadcasterFunc_3_2 : ITokenBroadcaster
{
    private readonly ILLMResponseProcessor _responseProcessor;
    private readonly ILogger _logger;
    //public event Func<object, string, Task> LineReceived;
    private CancellationTokenSource _cancellationTokenSource;
    private bool _isPrimaryLlm;
    private bool _isFuncCalled;
    public TokenBroadcasterFunc_3_2(ILLMResponseProcessor responseProcessor, ILogger logger)
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
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        var chunkServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse) chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>tool<|end_header_id|>", "<Function Response:> ") + "\n";
        else chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>user<|end_header_id|>", "<User:> ") + "\n";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
        chunkServiceObj.LlmMessage = "<Assistant:> ";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
        int stopAfter = 1;
        if (sendOutput) stopAfter = 2;
        sendOutput = true;

        var lineBuilder = new StringBuilder();
        var llmOutFull = new StringBuilder();
        _isFuncCalled = false;
        var cancellationToken = _cancellationTokenSource.Token;
        int stopCount = 0;


        while (!cancellationToken.IsCancellationRequested)
        {
            byte[] buffer = new byte[1024];
            int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
            string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
            //tokenBuilder.Append(textChunk);
            llmOutFull.Append(textChunk);
            chunkServiceObj = new LLMServiceObj(serviceObj);
            chunkServiceObj.LlmMessage = textChunk;
            if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
            string llmOutStr = llmOutFull.ToString();
            int eotIdCount = CountOccurrences(llmOutStr, "<|eot_id|>");

            if (eotIdCount > stopCount)
            {
                stopCount++;
                _logger.LogInformation($" Stop count {stopCount} output is {llmOutStr}");

            }
            if (stopCount == stopAfter)
            {
                await ProcessLine(llmOutStr, serviceObj);
                _logger.LogInformation($" Cancel due to {stopCount} <|eot_id|> detected ");
                _cancellationTokenSource.Cancel(); // Cancel after second <|eot_id|>}

            }
        }

        if (!_isPrimaryLlm && !_isFuncCalled)
        {
            string llmOutput = llmOutFull.ToString().Replace("\n", " ");
            var finalServiceObj = new LLMServiceObj(serviceObj);
            finalServiceObj.LlmMessage = llmOutput;
            finalServiceObj.IsFunctionCallResponse = true;
            await _responseProcessor.ProcessLLMOutput(finalServiceObj);
            _logger.LogInformation($" --> Sent redirected LLM Output {finalServiceObj.LlmMessage}");
        }
        _logger.LogInformation(" --> Finished LLM Interaction ");
    }

    private int CountOccurrences(string source, string substring)
    {
        int count = 0;
        int index = 0;

        while ((index = source.IndexOf(substring, index)) != -1)
        {
            count++;
            index += substring.Length;
        }

        return count;
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
    private async Task ProcessLine(string line, LLMServiceObj serviceObj)
    {
        //LLMServiceObj responseServiceObj = new LLMServiceObj() { SessionId = sessionId, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
        var responseServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse)
        {
            responseServiceObj.LlmMessage = "</functioncall-complete>";
            if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
        }
        else
        {
            (string jsonLine, string functionName) = ParseInputForJson(line);
            //string cleanLine = line;
            if (line != jsonLine)
            {
                _logger.LogInformation($" ProcessLLMOutput(call_func) -> {jsonLine}");

                // TODO send the function call achknowledgement back to calling llm :   forwardFuncServiceObj.LlmMessage = $"Please wait calling {functionName} function. Be patient this may take some time";
                //responseServiceObj = new LLMServiceObj() { SessionId = sessionId, UserInput = userInput, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
                responseServiceObj.LlmMessage = "</functioncall>";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                responseServiceObj.LlmMessage = "";
                responseServiceObj.IsFunctionCall = true;
                responseServiceObj.JsonFunction = jsonLine;
                if (!String.IsNullOrEmpty(functionName))
                {
                    responseServiceObj.FunctionName = functionName;
                }
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
    private static (string json, string functionName) ParseInputForJson(string input)
    {
        // Find the start and end of the function header (between <| and the first |)
        int headerStart = input.IndexOf("<|");
        int headerEnd = input.IndexOf('|', headerStart + 2);

        // If no valid function header is found, return input as-is
        if (headerStart == -1 || headerEnd == -1)
        {
            return (input, "");
        }

        // Extract the function name from between <| and the first |
        string functionName = input.Substring(headerStart + 2, headerEnd - (headerStart + 2)).Trim();

        // The JSON part starts right after the first |
        int jsonStart = headerEnd + 1;
        int jsonEnd = input.IndexOf("><|eot_id|>", jsonStart);

        // If no valid JSON end marker is found, return input as-is
        if (jsonEnd == -1)
        {
            return (input, functionName);
        }

        // Extract the JSON content between | and ><|eot_id|>
        string jsonContent = input.Substring(jsonStart, jsonEnd - jsonStart).Trim();

        return (JsonSanitizer.SanitizeJson(jsonContent), functionName);
    }

}
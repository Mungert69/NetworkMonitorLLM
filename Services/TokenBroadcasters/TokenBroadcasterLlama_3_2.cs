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
public class TokenBroadcasterLlama_3_2 : TokenBroadcasterBase
{

   public TokenBroadcasterLlama_3_2(ILLMResponseProcessor responseProcessor, ILogger logger) 
        : base(responseProcessor, logger) { }
    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, bool sendOutput = true)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        _responseProcessor.SendOutput = sendOutput;
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        var chunkServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse) chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>ipython<|end_header_id|>\\\n\\\n", "<Function Response:>");
        else chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>user<|end_header_id|>\\\n\\\n", "<User:>");
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
        string copyUserInput = userInput;
        //int startIndex = userInput.IndexOf('/');
        int stopAfter = 2;
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
            eotIdCount += CountOccurrences(llmOutStr, "<|eom_id|>");

            if (eotIdCount > stopCount)
            {
                stopCount++;
                if (llmOutStr.Contains("<|start_header_id|>assistant<|eot_id|>")) stopAfter = 2;
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

      protected override  (string json, string functionName) ParseInputForJson(string input)
    {
        // Find the start of the function name
        int headerStart = input.IndexOf("{\"name\": \"");
        if (headerStart == -1)
        {
            return (input, "");
        }

        // Extract the function name
        int functionNameStart = headerStart + "{\"name\": \"".Length;
        int functionNameEnd = input.IndexOf("\"", functionNameStart);
        if (functionNameEnd == -1)
        {
            return (input, "");
        }
        string functionName = input.Substring(functionNameStart, functionNameEnd - functionNameStart);

        // Find the parameters in the JSON format
        string paramStr = "\"parameters\"";
        int paramsStart = input.IndexOf(paramStr, functionNameEnd);
        if (paramsStart == -1)
        {
            return (input, functionName);  // No parameters found
        }

        // Extract the JSON parameters part
        int jsonStart = input.IndexOf("{", paramsStart + paramStr.Length);
        int braceCount = 0;
        int jsonEnd = -1;

        // Traverse the JSON starting point to find the matching closing brace
        for (int i = jsonStart; i < input.Length; i++)
        {
            if (input[i] == '{') braceCount++;
            else if (input[i] == '}') braceCount--;

            if (braceCount == 0)
            {
                jsonEnd = i;
                break;
            }
        }

        // Check if we found a valid JSON block
        if (jsonEnd == -1 || jsonEnd <= jsonStart)
        {
            return (input, functionName);
        }

        // Extract the JSON object for parameters
        string jsonContent = input.Substring(jsonStart, jsonEnd - jsonStart + 1).Trim();

        return (JsonSanitizer.SanitizeJson(jsonContent), functionName);
    }


}
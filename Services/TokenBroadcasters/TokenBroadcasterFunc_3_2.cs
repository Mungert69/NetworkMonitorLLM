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
public class TokenBroadcasterFunc_3_2 : TokenBroadcasterBase
{

   public TokenBroadcasterFunc_3_2(ILLMResponseProcessor responseProcessor, ILogger logger) 
        : base(responseProcessor, logger) { }

    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput,  int countEOT,bool sendOutput = true)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        _responseProcessor.SendOutput = sendOutput;
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        var chunkServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse) chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>tool<|end_header_id|>\\\n\\\n", "<Function Response:> ") ;
        else chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>user<|end_header_id|>\\\n\\\n", "<User:> ") + "\n";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
          int stopAfter = 2+countEOT;
        if (sendOutput) stopAfter = 2+countEOT;
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

     // Updated ParseInputForJson to handle multiple function calls
        protected override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var functionCalls = new List<(string json, string functionName)>();

            int tagStart = input.IndexOf("<|start_header_id|>assistant<|end_header_id|>");
            while (tagStart != -1)
            {
                int tagStartLength = "<|start_header_id|>assistant<|end_header_id|>\n\n>>>all\n".Length;
                string noHeaderLine = input.Substring(tagStart + tagStartLength).Trim();

                int headerStart = noHeaderLine.IndexOf(">>>");
                if (headerStart == -1) break;
                
                noHeaderLine = noHeaderLine.Substring(headerStart + 3);
                int headerEnd = noHeaderLine.IndexOf('\n');
                if (headerEnd == -1) break;

                string functionName = noHeaderLine.Substring(0, headerEnd).Trim();
                int jsonStart = headerEnd + 1;
                int jsonEnd = noHeaderLine.IndexOf("<|eot_id|>", jsonStart);

                if (jsonEnd == -1) break;

                string jsonContent = noHeaderLine.Substring(jsonStart, jsonEnd - jsonStart).Trim();
                functionCalls.Add((JsonSanitizer.SanitizeJson(jsonContent), functionName));

                // Move to the next function call in the input (if any)
                tagStart = input.IndexOf("<|start_header_id|>assistant<|end_header_id|>", jsonEnd);
            }

            return functionCalls;
        }
    

}
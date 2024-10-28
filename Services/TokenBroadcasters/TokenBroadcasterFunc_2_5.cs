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
public class TokenBroadcasterFunc_2_5 : TokenBroadcasterBase
{

   public TokenBroadcasterFunc_2_5(ILLMResponseProcessor responseProcessor, ILogger logger) 
        : base(responseProcessor, logger) { }
  
    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, bool sendOutput = true)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        _responseProcessor.SendOutput = sendOutput;
         _isPrimaryLlm = serviceObj.IsPrimaryLlm;
         var chunkServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse) chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>tool<|end_header_id|>\\\n\\\n", "<Function Response:> ");
        else chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>user<|end_header_id|>\\\n\\\n", "<User:> ")+"\n";
         if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
       
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

            //_logger.LogInformation($"EOT {eotIdCount}Output: {textChunk}");
            if (eotIdCount > stopCount)
            {
                stopCount++;
                // Process the full output only after the stopCount occurrence of <|eot_id|>
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
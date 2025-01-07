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

    public TokenBroadcasterFunc_2_5(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
         : base(responseProcessor, logger)
    {
        _xmlFunctionParsing = xmlFunctionParsing;
    }

    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, int countEOT, bool sendOutput = true)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        _responseProcessor.SendOutput = sendOutput;
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        var chunkServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse) chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>tool<|end_header_id|>\\\n\\\n", "<Function Response:> ");
        else chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>user<|end_header_id|>\\\n\\\n", "<User:> ") + "\n";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);

        int stopAfter = 2 + countEOT;
        if (sendOutput) stopAfter = 2 + countEOT;
        sendOutput = true;

        var lineBuilder = new StringBuilder();
        var llmOutFull = new StringBuilder();
        _isFuncCalled = false;
        int stopCount = 0;

        try
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                byte[] buffer = new byte[1024];
                int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
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
                llmOutput = llmOutput.Replace("<|start_header_id|>assistant<|end_header_id|>", "")
                                                             .Replace("<|eot_id|>", ""); // Additional replacement

                var finalServiceObj = new LLMServiceObj(serviceObj);
                finalServiceObj.LlmMessage = llmOutput;
                finalServiceObj.IsFunctionCallResponse = true;
                await _responseProcessor.ProcessLLMOutput(finalServiceObj);
                _logger.LogInformation($" --> Sent redirected LLM Output {finalServiceObj.LlmMessage}");
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Read operation canceled due to CancellationToken.");

            // Send a tidy-up message
            var finalChunkServiceObj = new LLMServiceObj(serviceObj)
            {
                LlmMessage = "\n"
            };
            if (_isPrimaryLlm)
                await _responseProcessor.ProcessLLMOutput(finalChunkServiceObj);
        }
        _logger.LogInformation(" --> Finished LLM Interaction ");
    }


    protected override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        string specialToken = "<|reserved_special_token_249|>";
        var functionCalls = new List<(string json, string functionName)>();

        int currentIndex = 0;
        while (true)
        {
            // Find the special token
            int tokenIndex = input.IndexOf(specialToken, currentIndex);
            if (tokenIndex == -1)
            {
                break; // No more special tokens found
            }

            // Extract the string after the special token
            string postTokenString = input.Substring(tokenIndex + specialToken.Length);

            // Find the start index of the JSON content
            int jsonStartIndex = postTokenString.IndexOf('{');
            if (jsonStartIndex == -1)
            {
                currentIndex = tokenIndex + specialToken.Length;
                continue; // No JSON found; move to the next token
            }

            // Extract the function name (content before JSON start)
            string functionNamePart = postTokenString.Substring(0, jsonStartIndex);
            string functionName = functionNamePart.Replace("\n", "").Trim();

            // Extract the JSON content
            string jsonContent = postTokenString.Substring(jsonStartIndex);

            // Find the end of the JSON content
            int jsonEndIndex = jsonContent.LastIndexOf('}');
            if (jsonEndIndex != -1)
            {
                jsonContent = jsonContent.Substring(0, jsonEndIndex + 1);
            }
            else
            {
                currentIndex = tokenIndex + specialToken.Length;
                continue; // Malformed JSON; move to the next token
            }

            // Sanitize and add the extracted JSON and function name to the list
            functionCalls.Add((JsonSanitizer.SanitizeJson(jsonContent), functionName));

            // Update currentIndex to continue searching after this function call
            currentIndex = tokenIndex + specialToken.Length + jsonEndIndex + 1;
        }

        return functionCalls;
    }

}
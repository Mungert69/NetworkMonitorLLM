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
public class TokenBroadcasterQwen_2_5 : TokenBroadcasterBase
{

    public TokenBroadcasterQwen_2_5(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
        : base(responseProcessor, logger)
    {
        _xmlFunctionParsing = xmlFunctionParsing;
    }


    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, int countEOT, bool sendOutput = true)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
      
        await SendLLMPrimaryChunk(serviceObj, "</llm-busy>");  
        _responseProcessor.SendOutput = sendOutput;
        var chunkServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse)
        {
            string funcChunk = userInput.Replace("<|im_start|>user\\\n<tool_response>\\\n", "<Function Response:> ");
            funcChunk = funcChunk.Replace("\\\n</tool_response", "");
            funcChunk = funcChunk.Replace("\n", "");
            chunkServiceObj.LlmMessage = funcChunk;
        }
        else chunkServiceObj.LlmMessage = userInput.Replace("<|im_start|>user\\\n", "<User:> ");

     await SendLLMPrimary(chunkServiceObj);

        int stopAfter = 2 + countEOT;
        if (sendOutput) stopAfter = 2 + countEOT;
        //sendOutput = true;

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
               await SendLLMPrimaryChunk(serviceObj,textChunk);
                string llmOutStr = llmOutFull.ToString();
                int eotIdCount = CountOccurrences(llmOutStr, "<|im_end|>");

                if (eotIdCount > stopCount)
                {
                    stopCount++;
                    _logger.LogInformation($"Stop after {stopAfter} : Stop count {stopCount} : output is {llmOutStr}");

                }
                if (stopCount == stopAfter)
                {
                    await ProcessLine(llmOutStr, serviceObj);
                    _logger.LogInformation($" Cancel due to {stopCount} <|im_end|> detected ");
                    _cancellationTokenSource.Cancel(); // Cancel after second <|eot_id|>}

                }
            }

            if (!_isPrimaryLlm && !_isFuncCalled)
            {
                string llmOutput = llmOutFull.ToString().Replace("\n", " ");
                llmOutput = llmOutput.Replace("<|im_start|>assistant", "")
                                                             .Replace("<|im_end|>", ""); // Additional replacement

                var finalServiceObj = new LLMServiceObj(serviceObj);
                finalServiceObj.LlmMessage = llmOutput;
                finalServiceObj.IsFunctionCallResponse = true;
                await SendLLM(finalServiceObj);
                _logger.LogInformation($" --> Sent redirected LLM Output {finalServiceObj.LlmMessage}");
            }
        }
      catch (OperationCanceledException)
        {
            _logger.LogInformation("Read operation canceled due to CancellationToken.");
            await SendLLMPrimaryChunk(serviceObj,"\n");
           
        }
        finally
        {
          await SendLLMPrimaryChunk(serviceObj, "</llm-listening>");    
        }
        _logger.LogInformation(" --> Finished LLM Interaction ");
    }


    protected override List<(string json, string functionName)> ParseInputForJson(string input)
    {
        var functionCalls = new List<(string json, string functionName)>();
        int tagStart = input.IndexOf("<tool_call>\n");
        int tagEnd;

        while (tagStart != -1)
        {
            // Move the starting index after the "<tool_call>\n" tag
            tagStart += "<tool_call>\n".Length;
            tagEnd = input.IndexOf("\n</tool_call>", tagStart);

            // If no matching end tag is found, break the loop
            if (tagEnd == -1) break;

            // Extract the JSON content between the tags
            string jsonContent = input.Substring(tagStart, tagEnd - tagStart).Trim();
            functionCalls.Add((JsonSanitizer.SanitizeJson(jsonContent), string.Empty));

            // Look for the next "<tool_call>\n" tag after the current end tag
            tagStart = input.IndexOf("<tool_call>\n", tagEnd + "</tool_call>".Length);
        }

        return functionCalls;
    }

}
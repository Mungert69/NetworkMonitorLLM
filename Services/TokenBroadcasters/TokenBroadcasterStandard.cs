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
public class TokenBroadcasterStandard : TokenBroadcasterBase
{

    private readonly string _defaultEOT = "<|eot_id|>";

    public TokenBroadcasterStandard(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
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
                int eotIdCount = CountOccurrences(llmOutStr, _defaultEOT);

                if (eotIdCount > stopCount)
                {
                    stopCount++;
                    _logger.LogInformation($" Stop count {stopCount} output is {llmOutStr}");

                }
                if (stopCount == stopAfter)
                {
                    await ProcessLine(llmOutStr, serviceObj);
                    _logger.LogInformation($" Cancel due to {stopCount} {_defaultEOT} detected ");
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
    }


}
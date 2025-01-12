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
         : base(responseProcessor, logger,xmlFunctionParsing)
    {


    }

    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        await SendHeader(serviceObj, userInput);

        var chunkServiceObj = new LLMServiceObj(serviceObj);

        var lineBuilder = new StringBuilder();
        var llmOutFull = new StringBuilder();
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
                await SendLLMPrimaryChunk(serviceObj, textChunk);
                string llmOutStr = llmOutFull.ToString();
                int eotIdCount = CountOccurrences(llmOutStr, _endTokens);

                if (eotIdCount > stopCount)
                {
                    stopCount++;
                    _logger.LogInformation($" Stop count {stopCount} output is {llmOutStr}");

                }
                if (stopCount == _stopAfter)
                {
                    await ProcessLine(llmOutStr, serviceObj);
                    _logger.LogInformation($" Cancel due to {stopCount} {_defaultEOT} detected ");
                    _cancellationTokenSource.Cancel(); // Cancel after second <|eot_id|>}

                }
            }
            if (!_isPrimaryLlm && !_isFuncCalled)
            {
                 string llmOutput = llmOutFull.ToString();
                    foreach (var token in _endTokens)
                    {
                        llmOutput = llmOutput.Replace(token, "");
                    }
                    llmOutput = llmOutput.Replace(_assistantHeader, "");

                    string extraMessage = "";
                    if (_isSystemLlm)
                    {
                        extraMessage += " From System LLM ";
                    }
                    else llmOutput = llmOutput.Replace("\n", " ");
                    var finalServiceObj = new LLMServiceObj(serviceObj);
                    finalServiceObj.LlmMessage = llmOutput;
                    finalServiceObj.IsFunctionCallResponse = true;
                    await _responseProcessor.ProcessLLMOutput(finalServiceObj);
                    _logger.LogInformation($" --> Sent redirected LLM Output {extraMessage}{finalServiceObj.LlmMessage}");
                    }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Read operation canceled due to CancellationToken.");
            await SendLLMPrimaryChunk(serviceObj, "\n");

        }
        finally
        {
            await SendLLMPrimaryChunk(serviceObj, "</llm-listening>");
        }
        _logger.LogInformation(" --> Finished LLM Interaction ");
    }


}
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
using System.Text.RegularExpressions;
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterLlama_3_2 : TokenBroadcasterBase
{

    public TokenBroadcasterLlama_3_2(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
         : base(responseProcessor, logger)
    {
        _xmlFunctionParsing = xmlFunctionParsing;
        _userReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n";
        _functionReplace = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n";
    }
    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput)
    {
        _logger.LogWarning(" Start BroadcastAsyc() ");
        await SendHeader(serviceObj, userInput);
      
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
                int eotIdCount = CountOccurrences(llmOutStr, "<|eot_id|>");
                eotIdCount += CountOccurrences(llmOutStr, "<|eom_id|>");

                if (eotIdCount > stopCount)
                {
                    stopCount++;
                    if (llmOutStr.Contains("<|start_header_id|>assistant<|eot_id|>")) _stopAfter = 2;
                    _logger.LogInformation($" Stop count {stopCount} output is {llmOutStr} ");

                }
                if (stopCount == _stopAfter)
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
            await SendLLMPrimaryChunk(serviceObj, "\n");

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

        // Define regex pattern to capture the function name and parameters JSON block
        var pattern = @"{""name"":\s*""(?<name>[^""]+)"",\s*""parameters"":\s*(?<parameters>{.*?})}";
        var matches = Regex.Matches(input, pattern);

        foreach (Match match in matches)
        {
            // Get function name and JSON parameters block
            var functionName = match.Groups["name"].Value;
            var jsonContent = match.Groups["parameters"].Value;

            // Optionally sanitize the JSON content
            functionCalls.Add((JsonSanitizer.SanitizeJson(jsonContent), functionName));
        }

        return functionCalls;
    }

}
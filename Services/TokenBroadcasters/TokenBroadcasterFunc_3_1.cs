using System;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using System.Linq;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;

namespace NetworkMonitor.LLM.Services
{
    public class TokenBroadcasterFunc_3_1 : TokenBroadcasterBase
    {

        public TokenBroadcasterFunc_3_1(ILLMResponseProcessor responseProcessor, ILogger logger, bool xmlFunctionParsing = false)
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
            _isFuncCalled = false;
            int stopCount = 0;

            try
            {
                while (!_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    byte[] buffer = new byte[255];
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
                        _logger.LogInformation($" Stop count {stopCount} output is {llmOutStr}");

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
                    await SendLLM(finalServiceObj);
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

            // Extract individual function call blocks using your custom method
            var functionCallExtracts = ExtractFunctionCalls(input);

            // Process each function call block
            foreach (var functionCallExtract in functionCallExtracts)
            {
                var processedCall = ProcessFunctionCall(functionCallExtract);
                if (processedCall != null)
                {
                    functionCalls.Add((processedCall.Value.json, processedCall.Value.functionName));
                }
            }

            return functionCalls;
        }

        private (string json, string functionName)? ProcessFunctionCall(string functionCall)
        {
            var match = Regex.Match(functionCall, @"<function=(\w+)>(.*?)</function>");
            if (match.Success)
            {
                string functionName = match.Groups[1].Value;
                string jsonArguments = match.Groups[2].Value;
                return (jsonArguments, functionName);

            }
            return null;
        }

        private List<string> ExtractFunctionCalls(string input)
        {
            return Regex.Matches(input, @"<function=\w+>.*?</function>")
                        .OfType<Match>()
                        .Select(m => m.Value)
                        .ToList();
        }
        private string RemoveFunctionCalls(string input)
        {
            return Regex.Replace(input, @"<function=\w+>.*?</function>", "").Trim();
        }
    }
}
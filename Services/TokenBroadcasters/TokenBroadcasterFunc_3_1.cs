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

        public TokenBroadcasterFunc_3_1(ILLMResponseProcessor responseProcessor, ILogger logger)
             : base(responseProcessor, logger) { }


        public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, int countEOT, bool sendOutput = true)
        {
            _logger.LogWarning(" Start BroadcastAsyc() ");
            _responseProcessor.SendOutput = sendOutput;
            _isPrimaryLlm = serviceObj.IsPrimaryLlm;
            var chunkServiceObj = new LLMServiceObj(serviceObj);
            if (serviceObj.IsFunctionCallResponse) chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>ipython<|end_header_id|>\\\n\\\n", "<Function Response:> ");
            else chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>user<|end_header_id|>\\\n\\\n", "<User:> ") + "\n";
            if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
            int stopAfter = 2 + countEOT;
            if (sendOutput) stopAfter = 2 + countEOT;
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
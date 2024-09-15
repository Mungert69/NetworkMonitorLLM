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
    public class TokenBroadcasterFunc_3_1 : ITokenBroadcaster
    {
        private readonly ILLMResponseProcessor _responseProcessor;
        private readonly ILogger _logger;
        //public event Func<object, string, Task> LineReceived;
        private CancellationTokenSource _cancellationTokenSource;
        private bool _isPrimaryLlm;
        private bool _isFuncCalled=false;

        public TokenBroadcasterFunc_3_1(ILLMResponseProcessor responseProcessor, ILogger logger)
        {
            _responseProcessor = responseProcessor;
            _logger = logger;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task ReInit(string sessionId)
        {
            _logger.LogInformation("Cancel due to ReInit called");
            await _cancellationTokenSource.CancelAsync();
        }

        public async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, bool sendOutput = true)
        {
            _logger.LogWarning("Start BroadcastAsync()");
            var outputBuilder = new StringBuilder();
            _isPrimaryLlm = serviceObj.IsPrimaryLlm;
            _isFuncCalled = false;
            var cancellationToken = _cancellationTokenSource.Token;

            while (!cancellationToken.IsCancellationRequested)
            {
                byte[] buffer = new byte[1];
                int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
                if (charRead == 0) break; // End of stream

                string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
                outputBuilder.Append(textChunk);

                var chunkServiceObj = new LLMServiceObj(serviceObj) { LlmMessage = textChunk };
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);

                if (outputBuilder.ToString().Contains("<|eot_id|>") || outputBuilder.ToString().Contains("<|eom_id|>"))
               
                //if (outputBuilder.ToString().Contains("<|eot_id|>") )
                {
                    await ProcessOutput(outputBuilder.ToString(), serviceObj);
                    outputBuilder.Clear();
                }
            }
            // TODO send completed conversation to calling llm if its a function call to this llm from a llm
            _logger.LogInformation("Finished LLM Interaction");
        }

        private async Task ProcessOutput(string output, LLMServiceObj serviceObj)
        {
            _logger.LogInformation($"sessionID={serviceObj.SessionId} output is =>{output}<=");

            // Process function calls
            var functionCalls = ExtractFunctionCalls(output);
            foreach (var functionCall in functionCalls)
            {
                 // TODO send the function call achknowledgement back to calling llm :   forwardFuncServiceObj.LlmMessage = $"Please wait calling {functionName} function. Be patient this may take some time";
                
                await ProcessFunctionCall(functionCall, serviceObj);
            }

            // Process regular output
            var cleanedOutput = RemoveFunctionCalls(output);
            if (!string.IsNullOrWhiteSpace(cleanedOutput))
            {
                var outputServiceObj = new LLMServiceObj(serviceObj) { LlmMessage = cleanedOutput };
                await _responseProcessor.ProcessLLMOutput(outputServiceObj);
            }
        }

        private async Task ProcessFunctionCall(string functionCall, LLMServiceObj serviceObj)
        {
            var match = Regex.Match(functionCall, @"<function=(\w+)>(.*?)</function>");
            if (match.Success)
            {
                string functionName = match.Groups[1].Value;
                string jsonArguments = match.Groups[2].Value;

                var functionServiceObj = new LLMServiceObj(serviceObj)
                {
                    IsFunctionCall = true,
                    FunctionName = functionName,
                    JsonFunction = jsonArguments
                };

                await _responseProcessor.ProcessFunctionCall(functionServiceObj);
                _isFuncCalled = true;
            }
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
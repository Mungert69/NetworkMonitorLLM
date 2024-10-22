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
        _logger.LogWarning(" Start BroadcastAsyc() ");
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        var chunkServiceObj = new LLMServiceObj(serviceObj);
        if (serviceObj.IsFunctionCallResponse) chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>ipython<|end_header_id|>\\\n\\\n", "<Function Response:> ") ;
        else chunkServiceObj.LlmMessage = userInput.Replace("<|start_header_id|>user<|end_header_id|>\\\n\\\n", "<User:> ") + "\n";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
          int stopAfter = 3;
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
            var finalServiceObj = new LLMServiceObj(serviceObj);
            finalServiceObj.LlmMessage = llmOutput;
            finalServiceObj.IsFunctionCallResponse = true;
            await _responseProcessor.ProcessLLMOutput(finalServiceObj);
            _logger.LogInformation($" --> Sent redirected LLM Output {finalServiceObj.LlmMessage}");
        }
        _logger.LogInformation(" --> Finished LLM Interaction ");
    }
 private int CountOccurrences(string source, string substring)
    {
        int count = 0;
        int index = 0;

        while ((index = source.IndexOf(substring, index)) != -1)
        {
            count++;
            index += substring.Length;
        }

        return count;
    }
   
        private async Task ProcessLine(string output, LLMServiceObj serviceObj)
        {
            //_logger.LogInformation($"sessionID={serviceObj.SessionId} output is =>{output}<=");

            // Process function calls
            var functionCalls = ExtractFunctionCalls(output);
            foreach (var functionCall in functionCalls)
            {
                 // TODO send the function call achknowledgement back to calling llm :   forwardFuncServiceObj.LlmMessage = $"Please wait calling {functionName} function. Be patient this may take some time";
                
                await ProcessFunctionCall(functionCall, serviceObj);
            }

            /*// Process regular output
            var cleanedOutput = RemoveFunctionCalls(output);
            if (!string.IsNullOrWhiteSpace(cleanedOutput))
            {
                var outputServiceObj = new LLMServiceObj(serviceObj) { LlmMessage = cleanedOutput };
                await _responseProcessor.ProcessLLMOutput(outputServiceObj);
            }*/
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
using OpenAI;
using OpenAI.Builders;
using OpenAI.Managers;
using OpenAI.ObjectModels;
using OpenAI.ObjectModels.RequestModels;
using OpenAI.ObjectModels.SharedModels;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using Microsoft.IdentityModel.Tokens;

namespace NetworkMonitor.LLM.Services;

public class OpenAIRunner : ILLMRunner
{
    private ILogger _logger;
    private ILLMResponseProcessor _responseProcessor;
    private OpenAIService _openAiService; // Interface to interact with OpenAI
    private List<ToolDefinition> _tools;
    private ConcurrentDictionary<string, DateTime> _activeSessions;

    private SemaphoreSlim _openAIRunnerSemaphore;
    private ConcurrentDictionary<string, List<ChatMessage>> _sessionHistories = new ConcurrentDictionary<string, List<ChatMessage>>();
    public string Type { get => "TurboLLM"; }
    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isPrimaryLlm;
    private bool _isFuncCalled;

    public bool IsStateReady { get => _isStateReady; }
    public bool IsStateStarting { get => _isStateStarting; }
    public bool IsStateFailed { get => _isStateFailed; }
    public OpenAIRunner(ILogger<OpenAIRunner> logger, ILLMResponseProcessor responseProcessor, OpenAIService openAiService, SemaphoreSlim openAIRunnerSemaphore)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _openAiService = openAiService;
        _openAIRunnerSemaphore = openAIRunnerSemaphore;
        _tools = ToolsBuilder.Tools;
        _activeSessions = new ConcurrentDictionary<string, DateTime>();
        _sessionHistories = new ConcurrentDictionary<string, List<ChatMessage>>();

    }

    public async Task StartProcess(LLMServiceObj serviceObj, DateTime currentTime)
    {
        _isStateStarting = true;
        _isStateReady = false;
        if (!_activeSessions.TryAdd(serviceObj.SessionId, currentTime))
        {
            _isStateStarting = false;
            _isStateReady = true;
            throw new InvalidOperationException("TurboLLM Assistant already running.");
        }
        _sessionHistories.GetOrAdd(serviceObj.SessionId, ToolsBuilder.GetSystemPrompt(_activeSessions[serviceObj.SessionId].ToString("yyyy-MM-ddTHH:mm:ss"), serviceObj));

        _logger.LogInformation($"Started session {serviceObj.SessionId} at {currentTime}.");
        // Here, you might want to send an initial message or perform other setup tasks.
        _isStateStarting = false;
        _isStateReady = true;
        _isStateFailed = false;
    }

    public async Task RemoveProcess(string sessionId)
    {
        _isStateReady = false;
        if (!_activeSessions.TryRemove(sessionId, out var lastActivity) || !_sessionHistories.TryRemove(sessionId, out var history))
        {
            _logger.LogWarning($"Attempted to remove non-existent session {sessionId}.");
            return;
        }
        _isStateReady = true;
        _isStateFailed = true;
        _logger.LogInformation($"Removed session {sessionId}. Last active at {lastActivity}. History had {history.Count} messages.");
    }


    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
        _isStateReady = false;
        
        var responseServiceObj = new LLMServiceObj(serviceObj);

        if (!_activeSessions.ContainsKey(serviceObj.SessionId))
        {
            _isStateFailed = true;
            _isStateReady = true;
            throw new Exception($"No Assistant found for session {serviceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
        }

        _logger.LogInformation("Sending input and waiting for response...");
         _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        _isFuncCalled = false;

        try
        {
            await _openAIRunnerSemaphore.WaitAsync(); // Wait to enter the semaphore

            string responseChoiceStr = "";
            // Retrieve or initialize the conversation history
            var history = _sessionHistories[serviceObj.SessionId];

            var chatMessage = new ChatMessage();
            if (serviceObj.IsFunctionCallResponse)
            {
                chatMessage.Role = "function";
                chatMessage.Name = serviceObj.FunctionName;
                responseServiceObj.LlmMessage = "Function Response: " + serviceObj.UserInput + "\n\n";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                responseServiceObj.LlmMessage = "</functioncall-complete>";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);

            }
            else
            {
                chatMessage.Role = "user";
                responseServiceObj.LlmMessage = "User: " + serviceObj.UserInput + "\n\n";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }

            chatMessage.Content = serviceObj.UserInput;
            history.Add(chatMessage);
            var completionResult = await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
            {
                Messages = history,
                Tools = _tools, // Your pre-defined tools
                ToolChoice = ToolChoice.Auto,
                MaxTokens = 1000,
                Model = Models.Gpt_3_5_Turbo_0125
            });

            if (completionResult.Successful)
            {
                var choice = completionResult.Choices.First();
                responseChoiceStr = choice.Message.Content ?? "";
                _logger.LogInformation($"Received response: {responseChoiceStr}");

                // Process any function calls
                if (choice.Message.ToolCalls != null)
                {
                    var fnCall = choice.Message.ToolCalls.First();

                    var fn = fnCall.FunctionCall;
                    string functionName = fn!.Name ?? "N/A";
                    _logger.LogInformation($"Function call detected: {functionName}");

                    var json = JsonSerializer.Serialize(fn.ParseArguments());
                    responseServiceObj.UserInput = serviceObj.UserInput;
                    responseServiceObj.LlmMessage = "</functioncall>";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    else
                    {
                        var forwardFuncServiceObj = new LLMServiceObj(responseServiceObj);
                        forwardFuncServiceObj.LlmMessage = $"Please wait calling function with parameters {json}. Be patient this may take some time";
                        forwardFuncServiceObj.IsFunctionCall = false;
                        forwardFuncServiceObj.IsFunctionCallResponse = true;
                        forwardFuncServiceObj.FunctionName = functionName;
                        await _responseProcessor.ProcessLLMOutput(forwardFuncServiceObj);
                        _logger.LogInformation($" --> Sent redirected LLM Function Output {forwardFuncServiceObj.LlmMessage}");

                    }

                    var functionResponseServiceObj = new LLMServiceObj(serviceObj);
                    functionResponseServiceObj.IsFunctionCall = true;
                    functionResponseServiceObj.JsonFunction = json;
                    _logger.LogInformation($" Sending json: {json}");
                    functionResponseServiceObj.FunctionName = functionName;

                    await _responseProcessor.ProcessFunctionCall(functionResponseServiceObj);
                    responseServiceObj.LlmMessage = "Function Call: " + json + "\n";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
                    responseChoiceStr = "";
                }

                if (!responseChoiceStr.IsNullOrEmpty())
                {

                    if (_isPrimaryLlm)
                    {
                        responseServiceObj.LlmMessage = "Assistant: " + responseChoiceStr + "\n\n";
                        await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
                    }
                    else
                    {
                        responseServiceObj.LlmMessage = responseChoiceStr;
                        await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    }
                   ;
                }
                responseServiceObj.LlmMessage = "<end-of-line>";
                responseServiceObj.TokensUsed = completionResult.Usage.TotalTokens;
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);

            }
            else
            {
                _logger.LogError($"Completion failed: {completionResult.Error}");
                throw new Exception($"Error from OpenAI : {completionResult.Error}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to process user input: {ex.Message}");
            throw;
        }
        finally
        {
            _openAIRunnerSemaphore.Release(); // Release the semaphore
            _isStateReady = true;
        }
    }

    private int CalculateTokens(string text)
    {
        // Basic token counting logic, could be improved with actual tokenization logic
        return text.Split(new char[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
    }

    // Implement other methods as needed...
}

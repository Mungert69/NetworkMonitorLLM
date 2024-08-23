using OpenAI;
using OpenAI.Builders;
using OpenAI.Managers;
using OpenAI.ObjectModels;
using OpenAI.ObjectModels.RequestModels;
using OpenAI.Tokenizer.GPT3;
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
    private IToolsBuilder _toolsBuilder;
    private ConcurrentDictionary<string, DateTime> _activeSessions;

    private SemaphoreSlim _openAIRunnerSemaphore;
    private ConcurrentDictionary<string, List<ChatMessage>> _sessionHistories = new ConcurrentDictionary<string, List<ChatMessage>>();
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionResponses = new ConcurrentDictionary<string, ChatMessage>();

    public string Type { get => "TurboLLM"; }
    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isPrimaryLlm;
    private bool _isFuncCalled;
    private string _serviceID;
    private int _maxTokens = 2000;

    public bool IsStateReady { get => _isStateReady; }
    public bool IsStateStarting { get => _isStateStarting; }
    public bool IsStateFailed { get => _isStateFailed; }
    public OpenAIRunner(ILogger<OpenAIRunner> logger, ILLMResponseProcessor responseProcessor, OpenAIService openAiService, ISystemParamsHelper systemParamsHelper, SemaphoreSlim openAIRunnerSemaphore)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _openAiService = openAiService;
        _openAIRunnerSemaphore = openAIRunnerSemaphore;
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        if (_serviceID == "Monitor") _toolsBuilder = new MonitorToolsBuilder();
        if (_serviceID == "Nmap") _toolsBuilder = new NmapToolsBuilder();
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
            throw new InvalidOperationException($"TurboLLM {_serviceID} Assistant already running.");
        }
        _sessionHistories.GetOrAdd(serviceObj.SessionId, _toolsBuilder.GetSystemPrompt(_activeSessions[serviceObj.SessionId].ToString("yyyy-MM-ddTHH:mm:ss"), serviceObj));

        _logger.LogInformation($"Started TurboLLM {_serviceID} Assistant with session id {serviceObj.SessionId} at {currentTime}.");
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
            _logger.LogWarning($"Attempted to stop TurboLLM {_serviceID} Assistant with non-existent session {sessionId}.");
            return;
        }
        _isStateReady = true;
        _isStateFailed = true;
        _logger.LogInformation($" Stopped TurboLLM {_serviceID} Assistant with session {sessionId}. Last active at {lastActivity}. History had {history.Count} messages.");
    }


    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
        _isStateReady = false;

        var responseServiceObj = new LLMServiceObj(serviceObj);

        if (!_activeSessions.ContainsKey(serviceObj.SessionId))
        {
            _isStateFailed = true;
            _isStateReady = true;
            throw new Exception($"No TurboLLM {_serviceID} Assistants found for session {serviceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
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
            chatMessage.Content = serviceObj.UserInput;
            if (serviceObj.IsFunctionCallResponse)
            {
                _pendingFunctionResponses.TryGetValue(serviceObj.FunctionCallId, out var funcChatMessage);



                if (funcChatMessage != null)
                {
                    chatMessage.Role = "tool";
                    chatMessage.Name = serviceObj.FunctionName;
                    chatMessage.ToolCallId = serviceObj.FunctionCallId;
                    history.Add(funcChatMessage);
                    history.Add(chatMessage);
                    _pendingFunctionResponses.TryRemove(serviceObj.FunctionCallId, out _);
                    responseServiceObj.LlmMessage = "Function Response: " + serviceObj.UserInput + "\n\n";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    responseServiceObj.LlmMessage = "</functioncall-complete>";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                }
                else
                {
                    responseServiceObj.LlmMessage = "Function Response: Failed to match function call to its response\n\n";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    responseServiceObj.LlmMessage = "</functioncall-complete>";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);

                }

            }
            else
            {
                chatMessage.Role = "user";
                responseServiceObj.LlmMessage = "User: " + serviceObj.UserInput + "\n\n";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                history.Add(chatMessage);
            }



            int tokenCount = CalculateTokens(history);
            if (tokenCount > _maxTokens)
            {
                _logger.LogInformation($"Token count ({tokenCount}) exceeded the limit, truncating history.");

                // Keep the first system message intact
                var systemMessage = history.First();
                history = history.Skip(1).ToList();

                // Remove messages until the token count is under the limit
                while (tokenCount > _maxTokens && history.Count > 1)
                {
                    history.RemoveAt(0); // Remove the oldest message
                    tokenCount = CalculateTokens(history);
                }

                // Restore the system message at the start
                history.Insert(0, systemMessage);
                _sessionHistories[serviceObj.SessionId] = history;
                _logger.LogInformation($"History truncated to {tokenCount} tokens.");
            }

            _logger.LogInformation($"History Token count: {tokenCount}");

            var completionResult = await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
            {
                Messages = history,
                Tools = _toolsBuilder.Tools, // Your pre-defined tools
                ToolChoice = ToolChoice.Auto,
                MaxTokens = 1000,
                Model = "gpt-4o-mini"
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
                    serviceObj.FunctionCallId = fnCall.Id;
                    serviceObj.FunctionName = functionName;

                    //chatMessage.Name = functionName;
                    _pendingFunctionResponses.TryAdd(fnCall.Id, choice.Message);
                    _logger.LogInformation($"Function call detected: {functionName}");

                    var json = JsonSerializer.Serialize(fn.ParseArguments());
                    responseServiceObj.UserInput = serviceObj.UserInput;
                    responseServiceObj.LlmMessage = "</functioncall>";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    else
                    {
                        var forwardFuncServiceObj = new LLMServiceObj(serviceObj);
                        forwardFuncServiceObj.LlmMessage = $"Please wait calling function with parameters {json}. Be patient this may take some time";
                        forwardFuncServiceObj.IsFunctionCall = false;
                        forwardFuncServiceObj.IsFunctionCallResponse = true;
                        //await _responseProcessor.ProcessLLMOutput(forwardFuncServiceObj);
                        //_logger.LogInformation($" --> Sent redirected LLM Function Output {forwardFuncServiceObj.LlmMessage}");

                    }

                    var functionResponseServiceObj = new LLMServiceObj(serviceObj);
                    functionResponseServiceObj.IsFunctionCall = true;
                    functionResponseServiceObj.JsonFunction = json;
                    _logger.LogInformation($" Sending json: {json}");
                    functionResponseServiceObj.FunctionName = functionName;

                    await _responseProcessor.ProcessFunctionCall(functionResponseServiceObj);
                    responseServiceObj.LlmMessage = "Function Call: " + functionName + "\n" + json + "\n";
                    if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
                    responseChoiceStr = "";
                }

                if (!responseChoiceStr.IsNullOrEmpty())
                {
                    var assistantChatMessage = new ChatMessage()
                    {
                        Role = "assistant",
                        Content = responseChoiceStr
                    };
                    history.Add(choice.Message);

                    if (_isPrimaryLlm)
                    {
                        responseServiceObj.IsFunctionCallResponse = false;
                        responseServiceObj.LlmMessage = "Assistant: " + responseChoiceStr + "\n\n";
                        await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
                    }
                    else
                    {
                        responseServiceObj.IsFunctionCallResponse = true;
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
                if (completionResult.Error != null)
                {
                    _logger.LogError($" {_serviceID} Assistant OpenAI Error : {completionResult.Error.Message}");
                    throw new Exception($" {_serviceID} Assistant OpenAI Error : {completionResult.Error.Message}");
                }
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


    private int CalculateTokens(IEnumerable<ChatMessage> messages)
    {
        int tokenCount = 0;

        foreach (var message in messages)
        {
            //_logger.LogInformation($"History: {message.Content}");
            if (!String.IsNullOrEmpty(message.Content)) tokenCount += TokenizerGpt3.TokenCount(message.Content);
        }

        return tokenCount;
    }

}

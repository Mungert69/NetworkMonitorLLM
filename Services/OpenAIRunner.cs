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
using NetworkMonitor.Service.Services.OpenAI;
using OpenAI.ObjectModels.ResponseModels;

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
    private ConcurrentDictionary<string, List<ChatMessage>> _messageHistories = new ConcurrentDictionary<string, List<ChatMessage>>();

    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionCalls = new ConcurrentDictionary<string, ChatMessage>();
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionResponses = new ConcurrentDictionary<string, ChatMessage>();

    public string Type { get => "TurboLLM"; }
    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isPrimaryLlm;
    //private bool _isFuncCalled;
    private string _serviceID;
    private int _maxTokens = 32000;

    public bool IsStateReady { get => _isStateReady; }
    public bool IsStateStarting { get => _isStateStarting; }
    public bool IsStateFailed { get => _isStateFailed; }
    public OpenAIRunner(ILogger<OpenAIRunner> logger, ILLMResponseProcessor responseProcessor, OpenAIService openAiService, ISystemParamsHelper systemParamsHelper, LLMServiceObj serviceObj, SemaphoreSlim openAIRunnerSemaphore)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _openAiService = openAiService;
        _openAIRunnerSemaphore = openAIRunnerSemaphore;
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _maxTokens = systemParamsHelper.GetMLParams().LlmOpenAICtxSize;
        if (_serviceID == "monitor") _toolsBuilder = new MonitorToolsBuilder(serviceObj.UserInfo);
        if (_serviceID == "nmap") _toolsBuilder = new NmapToolsBuilder();
        if (_serviceID == "meta") _toolsBuilder = new MetaToolsBuilder();
        _activeSessions = new ConcurrentDictionary<string, DateTime>();
        _sessionHistories = new ConcurrentDictionary<string, List<ChatMessage>>();

    }

    public Task StartProcess(LLMServiceObj serviceObj, DateTime currentTime)
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
        return Task.CompletedTask;
    }

    public Task RemoveProcess(string sessionId)
    {
        _isStateReady = false;
        if (!_activeSessions.TryRemove(sessionId, out var lastActivity) || !_sessionHistories.TryRemove(sessionId, out var history))
        {
            _logger.LogWarning($"Attempted to stop TurboLLM {_serviceID} Assistant with non-existent session {sessionId}.");
            _isStateReady = true;
            _isStateFailed = true;
            return Task.CompletedTask;
        }
        _isStateReady = true;
        _isStateFailed = true;
        _logger.LogInformation($" Stopped TurboLLM {_serviceID} Assistant with session {sessionId}. Last active at {lastActivity}. History had {history.Count} messages.");
        return Task.CompletedTask;
    }



    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
        _isStateReady = false;

        var responseServiceObj = new LLMServiceObj(serviceObj);
        var assistantChatMessage = ChatMessage.FromAssistant("");
        bool canAddFuncMessage = false;
        bool isFuncMessage = false;

        if (!_activeSessions.ContainsKey(serviceObj.SessionId))
        {
            _isStateFailed = true;
            _isStateReady = true;
            throw new Exception($"No TurboLLM {_serviceID} Assistants found for session {serviceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
        }

        _logger.LogInformation("Sending input and waiting for response...");
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;

        try
        {
            await _openAIRunnerSemaphore.WaitAsync(); // Wait to enter the semaphore

            // Retrieve or initialize the conversation history
            var history = _sessionHistories[serviceObj.SessionId];
            var messageHistory = _messageHistories.GetOrAdd(serviceObj.MessageID, new List<ChatMessage>());
            ChatMessage chatMessage;

            if (serviceObj.IsFunctionCallResponse)
            {
                isFuncMessage = true;
                canAddFuncMessage = HandleFunctionCallResponse(serviceObj, messageHistory, responseServiceObj);
            }
            else
            {
                chatMessage = ChatMessage.FromUser(serviceObj.UserInput);
                responseServiceObj.LlmMessage = "User: " + serviceObj.UserInput + "\n\n";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                messageHistory.Add(chatMessage);
            }

            var currentHistory = new List<ChatMessage>(history.Concat(messageHistory));

            var completionResult = await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
            {
                Messages = currentHistory,
                Tools = _toolsBuilder.Tools, // Your pre-defined tools
                ToolChoice = ToolChoice.Auto,
                MaxTokens = 1000,
                Model = "gpt-4o-mini"
            });


            if (completionResult.Successful)
            {
                var tokensUsed = completionResult.Usage.TotalTokens;
                ChatChoiceResponse choice = completionResult.Choices.First();
                var responseChoiceStr = choice.Message.Content ?? "";

                if (choice.Message.ToolCalls != null && choice.Message.ToolCalls.Any())
                {
                    isFuncMessage = true;
                    _pendingFunctionCalls.TryAdd(serviceObj.MessageID, choice.Message);
                    foreach (var fnCall in choice.Message.ToolCalls)
                    {

                        await HandleFunctionCallAsync(serviceObj, fnCall, responseServiceObj, messageHistory);
                    }
                }
                else
                {
                    await ProcessAssistantMessageAsync(choice, tokensUsed, responseServiceObj, assistantChatMessage, messageHistory, history, serviceObj);
                }
                if (!isFuncMessage || (isFuncMessage && canAddFuncMessage))
                {

                    history.Concat(messageHistory);
                    history.Add(assistantChatMessage);
                    TruncateTokens(history, serviceObj);
                }
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
            throw;
        }
        finally
        {
            _openAIRunnerSemaphore.Release(); // Release the semaphore
            _isStateReady = true;
        }
    }

    private bool HandleFunctionCallResponse(LLMServiceObj serviceObj, List<ChatMessage> messageHistory, LLMServiceObj responseServiceObj)
    {
        // Retrieve the function response based on the function call ID
        _pendingFunctionResponses.TryGetValue(serviceObj.FunctionCallId, out var funcResponseChatMessage);

        if (funcResponseChatMessage != null)
        {
            // Add the response content to the corresponding chat message
            funcResponseChatMessage.Content = serviceObj.UserInput;
            responseServiceObj.LlmMessage = "Function Response: " + serviceObj.UserInput + "\n\n";

            // Process the LLM output if it's the primary LLM
            if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);

            // Indicate the function call has been completed
            responseServiceObj.LlmMessage = "</functioncall-complete>";
            if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);

            // Check if there are any pending function calls associated with the current message
            _pendingFunctionCalls.TryGetValue(serviceObj.MessageID, out var funcCallChatMessage);

            if (funcCallChatMessage != null)
            {
                // Check if all function calls associated with the message have received responses
                bool allResponsesReceived = funcCallChatMessage.ToolCalls
                .All(tc =>
                    _pendingFunctionResponses.TryGetValue(tc.Id, out var response) &&
                    !string.IsNullOrEmpty(response.Content) // Ensure the response has some content
                );

                if (allResponsesReceived)
                {
                    // Add the function call and responses to the message history
                    messageHistory.Add(funcCallChatMessage);
                    foreach (var toolCall in funcCallChatMessage.ToolCalls)
                    {
                        if (_pendingFunctionResponses.TryGetValue(toolCall.Id, out var response))
                        {
                            messageHistory.Add(response);
                            _pendingFunctionResponses.TryRemove(toolCall.Id, out _);
                        }
                    }

                    // Clean up the pending function call
                    _pendingFunctionCalls.TryRemove(serviceObj.MessageID, out _);
                    return true; // Indicates that the function call response was handled successfully
                }
            }
        }
        else
        {
            // Log a failure to match function call to its response
            responseServiceObj.LlmMessage = $"Function Response: Failed to match function call {responseServiceObj.FunctionName} to its response\n\n";
            if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);

            // Mark the function call as complete
            responseServiceObj.LlmMessage = "</functioncall-complete>";
            if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);
        }

        return false; // Indicates that the function call response could not be fully handled
    }

    private async Task HandleFunctionCallAsync(LLMServiceObj serviceObj, ToolCall fnCall, LLMServiceObj responseServiceObj, List<ChatMessage> messageHistory)
    {
        var fn = fnCall.FunctionCall;
        string functionName = fn?.Name ?? "N/A";

        if (fnCall.Id == null)
        {
            throw new Exception($" {_serviceID} Assistant OpenAI Error : Api call returned a Function with no Id");
        }

        serviceObj.FunctionCallId = fnCall.Id;
        serviceObj.FunctionName = functionName;
        var chatMessage = ChatMessage.FromTool("", fnCall.Id);
        chatMessage.Name = functionName;
        _pendingFunctionResponses.TryAdd(fnCall.Id, chatMessage);

        _logger.LogInformation($"Function call detected: {functionName}");

        var json = JsonSerializer.Serialize(fn.ParseArguments());
        responseServiceObj.UserInput = serviceObj.UserInput;
        responseServiceObj.LlmMessage = "</functioncall>";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);

        var functionResponseServiceObj = new LLMServiceObj(serviceObj)
        {
            IsFunctionCall = true,
            JsonFunction = json,
            FunctionName = functionName
        };
        _logger.LogInformation($" Sending json: {json}");

        await _responseProcessor.ProcessFunctionCall(functionResponseServiceObj);

        responseServiceObj.LlmMessage = "Function Call: " + functionName + "\n" + json + "\n";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
    }

    private async Task ProcessAssistantMessageAsync(ChatChoiceResponse choice, int tokensUsed ,LLMServiceObj responseServiceObj, ChatMessage assistantChatMessage, List<ChatMessage> messageHistory, List<ChatMessage> history, LLMServiceObj serviceObj)
    {
        var responseChoiceStr = choice.Message.Content ?? "";
        _logger.LogInformation($"Assistant output : {responseChoiceStr}");

        if (choice.FinishReason == "stop")
        {
            assistantChatMessage.Content = responseChoiceStr;
            responseServiceObj.IsFunctionCallResponse = false;
            responseServiceObj.LlmMessage = "Assistant: " + responseChoiceStr + "\n\n";
            if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
            else
            {
                responseServiceObj.IsFunctionCallResponse = true;
                responseServiceObj.LlmMessage = responseChoiceStr;
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }

            messageHistory.Add(assistantChatMessage);
   
        }

        responseServiceObj.LlmMessage = "<end-of-line>";
        responseServiceObj.TokensUsed = tokensUsed;
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
    }


    private void TruncateTokens(List<ChatMessage> history, LLMServiceObj serviceObj)
    {
        int tokenCount = CalculateTokens(history);
        _logger.LogInformation($"History Token count: {tokenCount}");

        if (tokenCount > _maxTokens)
        {
            _logger.LogInformation($"Token count ({tokenCount}) exceeded the limit, truncating history.");

            // Keep the first system message intact
            var systemMessage = history.First();
            history = history.Skip(1).ToList();

            // Remove messages until the token count is under the limit
            while (tokenCount > _maxTokens)
            {
                var removeMessage = history[0];
                var toolCallId = removeMessage.ToolCallId;
                if (string.IsNullOrEmpty(toolCallId))
                {
                    history.RemoveAt(0);
                }
                else
                {
                    for (int i = history.Count - 1; i >= 0; i--)
                    {
                        if (history[i].ToolCallId == removeMessage.ToolCallId)
                        {
                            history.RemoveAt(i);
                        }
                    }
                }

                // Recalculate tokens after removal
                tokenCount = CalculateTokens(history);
            }

            // Re-add the system message to the beginning of the list
            history.Insert(0, systemMessage);

            // Update the session history
            _sessionHistories[serviceObj.SessionId] = history;
            _logger.LogInformation($"History truncated to {tokenCount} tokens.");
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

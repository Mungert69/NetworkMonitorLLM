using OpenAI;
using OpenAI.Builders;
using OpenAI.Managers;
using OpenAI.ObjectModels;
using OpenAI.ObjectModels.RequestModels;
using OpenAI.Tokenizer.GPT3;
using OpenAI.ObjectModels.SharedModels;
using OpenAI.ObjectModels.ResponseModels;
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
using NetworkMonitor.Objects.Factory;

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
    //private ConcurrentDictionary<string, string> _toolCallMetadata = new ConcurrentDictionary<string, string>();

    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionCalls = new ConcurrentDictionary<string, ChatMessage>();
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionResponses = new ConcurrentDictionary<string, ChatMessage>();

    public string Type { get => "TurboLLM"; }
    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isPrimaryLlm;
    private bool _isSystemLlm;
    //private bool _isFuncCalled;
    private string _serviceID;
    private int _maxTokens = 2000;
    private string _gptModel = "gpt-4o-mini";

    public bool IsStateReady { get => _isStateReady; }
    public bool IsStateStarting { get => _isStateStarting; }
    public bool IsStateFailed { get => _isStateFailed; }
#pragma warning disable CS8618
    public OpenAIRunner(ILogger<OpenAIRunner> logger, ILLMResponseProcessor responseProcessor, OpenAIService openAiService, ISystemParamsHelper systemParamsHelper, LLMServiceObj serviceObj, SemaphoreSlim openAIRunnerSemaphore)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _openAiService = openAiService;
        _openAIRunnerSemaphore = openAIRunnerSemaphore;
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _maxTokens = systemParamsHelper.GetMLParams().LlmOpenAICtxSize;
        _gptModel = systemParamsHelper.GetMLParams().LlmGptModel;
        if (_serviceID == "monitor") _toolsBuilder = new MonitorToolsBuilder(serviceObj.UserInfo);
        if (_serviceID == "blogmonitor") _toolsBuilder = new BlogMonitorToolsBuilder(serviceObj.UserInfo);

        if (_serviceID == "nmap") _toolsBuilder = new NmapToolsBuilder();
        if (_serviceID == "meta") _toolsBuilder = new MetaToolsBuilder();
        if (_serviceID == "search") _toolsBuilder = new SearchToolsBuilder();
        if (_serviceID == "reportdata") _toolsBuilder = new ReportDataToolsBuilder();
        _maxTokens = AccountTypeFactory.GetAccountTypeByName(serviceObj.UserInfo.AccountType!).ContextSize;
        _activeSessions = new ConcurrentDictionary<string, DateTime>();
        _sessionHistories = new ConcurrentDictionary<string, List<ChatMessage>>();

    }
#pragma warning restore CS8618
    public Task StartProcess(LLMServiceObj serviceObj, DateTime currentTime)
    {
        _isStateStarting = true;
        _isStateReady = false;
        _responseProcessor.IsManagedMultiFunc = true;

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
        responseServiceObj.TokensUsed = 0;
        var assistantChatMessage = ChatMessage.FromAssistant("");
        bool canAddFuncMessage = false;

        if (!_activeSessions.ContainsKey(serviceObj.SessionId))
        {
            _isStateFailed = true;
            _isStateReady = true;
            throw new Exception($"No TurboLLM {_serviceID} Assistants found for session {serviceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
        }

        if (serviceObj.IsFunctionStillRunning)
        {
            //TODO work out how to use function still running messages
            _logger.LogInformation("Ignoring FunctionStillRunning message.");
            return;
        }

        _logger.LogInformation("Sending input and waiting for response...");
        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        _isSystemLlm = serviceObj.IsSystemLlm;

        try
        {
            await _openAIRunnerSemaphore.WaitAsync(); // Wait to enter the semaphore

            // Retrieve or initialize the conversation history
            var history = _sessionHistories[serviceObj.SessionId];
            var messageHistory = _messageHistories.GetOrAdd(serviceObj.MessageID, new List<ChatMessage>());
            ChatMessage chatMessage;

            if (serviceObj.IsFunctionCallResponse)
            {
                canAddFuncMessage = HandleFunctionCallResponse(serviceObj, messageHistory, responseServiceObj);
            }
            else
            {
                chatMessage = ChatMessage.FromUser(serviceObj.UserInput);
                responseServiceObj.LlmMessage = "<User:> " + serviceObj.UserInput + "\n\n";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                messageHistory.Add(chatMessage);
            }

            if (!serviceObj.IsFunctionCallResponse || (serviceObj.IsFunctionCallResponse && canAddFuncMessage))
            {
                var currentHistory = new List<ChatMessage>(history.Concat(messageHistory));
                ChatCompletionCreateResponse completionResult;
                if (_toolsBuilder.Tools == null || _toolsBuilder.Tools.Count == 0)
                {
                    completionResult = await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
                    {
                        Messages = currentHistory,
                        MaxTokens = 1000,
                        Model = _gptModel
                    });
                }
                else
                {
                    completionResult = await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
                    {
                        Messages = currentHistory,
                        Tools = _toolsBuilder.Tools, // Your pre-defined tools
                        ToolChoice = ToolChoice.Auto,
                        MaxTokens = 1000,
                        Model = _gptModel
                    });
                }


                if (completionResult.Successful)
                {

                    responseServiceObj.TokensUsed = completionResult.Usage.TotalTokens;
                    if (completionResult.Usage != null && completionResult.Usage.PromptTokensDetails != null)
                    {
                        _logger.LogInformation($"Cached Prompt Tokens {completionResult.Usage.PromptTokensDetails.CachedTokens}");
                    }
                    ChatChoiceResponse choice = completionResult.Choices.First();
                    var responseChoiceStr = choice.Message.Content ?? "";

                    if (choice.Message.ToolCalls != null && choice.Message.ToolCalls.Any())
                    {
                        _pendingFunctionCalls.TryAdd(serviceObj.MessageID, choice.Message);
                        // Create a unique placeholder ID for tracking

                        // Add a lightweight placeholder to history indicating a tool call is in progress.
                        // This avoids the OpenAI API error of having an incomplete response.
                        var placeholderUser = ChatMessage.FromUser($"{serviceObj.UserInput} : us message_id <|{serviceObj.MessageID}|> to track the function calls");
                        history.Add(placeholderUser);
                        var assistantMessage = new StringBuilder($"I have called the following functions : ");
                        foreach (ToolCall fnCall in choice.Message.ToolCalls)
                        {
                            if (fnCall.FunctionCall != null)
                            {
                                var funcName = fnCall.FunctionCall.Name;
                                var funcArgs = fnCall.FunctionCall.Arguments;
                                assistantMessage.Append($" Name {funcName} Arguments {funcArgs} : ");
                                // Handle the function call asynchronously and remove the placeholder when complete
                                await HandleFunctionCallAsync(serviceObj, fnCall, responseServiceObj, assistantChatMessage);

                            }
                        }
                        assistantMessage.Append($" using message_id <|{serviceObj.MessageID}|> . Please wait it may take some time to complete.");
                        var placeholderAssistant = ChatMessage.FromAssistant(assistantMessage.ToString());
                        history.Add(placeholderAssistant);

                    }
                    else
                    {
                        await ProcessAssistantMessageAsync(choice, responseServiceObj, assistantChatMessage, messageHistory, history, serviceObj);
                    }



                    if (!string.IsNullOrEmpty(assistantChatMessage.Content))
                    {
                        history.AddRange(messageHistory);
                        history.Add(assistantChatMessage);
                    }
                    TruncateTokens(history, serviceObj);

                }
                else
                {
                    if (completionResult.Error != null)
                    {
                        _logger.LogError($" {_serviceID} Assistant OpenAI Error : {completionResult.Error.Message}");
                        throw new Exception($" {_serviceID} Assistant OpenAI Error : {completionResult.Error.Message}");
                    }
                }
                await _responseProcessor.UpdateTokensUsed(responseServiceObj);
            }

        }
        catch
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
        ChatMessage funcResponseChatMessage;
        // Check if there are any pending function calls associated with the current message
        _pendingFunctionCalls.TryGetValue(serviceObj.MessageID, out var funcCallChatMessage);
        if (funcCallChatMessage != null && funcCallChatMessage.ToolCalls != null)
        {
            // Check if a response for the given FunctionCallId already exists in the dictionary
            if (_pendingFunctionResponses.TryGetValue(serviceObj.FunctionCallId, out var existingFuncResponseChatMessage))
            {
                // Update the existing response with the new content
                funcResponseChatMessage = existingFuncResponseChatMessage;
                funcResponseChatMessage.Content = serviceObj.UserInput;
            }
            else
            {
                // Create a new ChatMessage for the function response if it doesn't exist
                funcResponseChatMessage = ChatMessage.FromTool("", serviceObj.FunctionCallId);
                funcResponseChatMessage.Name = serviceObj.FunctionName;
                funcResponseChatMessage.Content = serviceObj.UserInput;

                // Add the new response to the dictionary
                _pendingFunctionResponses.TryAdd(serviceObj.FunctionCallId, funcResponseChatMessage);
            }

            // Add the response content to the corresponding chat message
            funcResponseChatMessage.Content = serviceObj.UserInput;
            responseServiceObj.LlmMessage = "<Function Response:> " + serviceObj.UserInput + "\n\n";

            // Process the LLM output if it's the primary LLM
            if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);

            bool allResponsesReceived = funcCallChatMessage.ToolCalls
                .All(tc => _pendingFunctionResponses.ContainsKey(tc.Id!));


            if (allResponsesReceived)
            {
                // Add the function call and responses to the message history
                messageHistory.Add(funcCallChatMessage);

                foreach (var toolCall in funcCallChatMessage.ToolCalls)
                {
                    if (_pendingFunctionResponses.TryGetValue(toolCall.Id!, out var response))
                    {

                        messageHistory.Add(response);
                        _pendingFunctionResponses.TryRemove(toolCall.Id!, out _);
                    }
                }

                // Clean up the pending function call
                _pendingFunctionCalls.TryRemove(serviceObj.MessageID, out _);
                // Mark the function call as complete
                responseServiceObj.LlmMessage = "</functioncall-complete>";
                if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);


                if (_sessionHistories.TryGetValue(serviceObj.SessionId, out var history))
                {
                    lock (history)
                    {
                        // Loop through the list from end to start to safely remove multiple items by index
                        for (int i = history.Count - 1; i >= 0; i--)
                        {
                            if (history[i].Content != null && history[i].Content.Contains("<|" + serviceObj.MessageID + "|>"))
                            {
                                history.RemoveAt(i);
                            }
                        }
                    }


                    _logger.LogInformation($"Successfully removed all placeholder messages with ID {serviceObj.MessageID} from history for session {serviceObj.SessionId}.");
                }
                else
                {
                    var message = $"Function Error: Could not find history for SessionID {serviceObj.SessionId} to remove placeholders.";
                    responseServiceObj.LlmMessage = message;
                    if (_isPrimaryLlm || _isSystemLlm) _responseProcessor.ProcessLLMOutputError(responseServiceObj);
                    _logger.LogError(message);
                }

                return true; // Indicates that the function call response was handled successfully

            }
        }
        else
        {
            responseServiceObj.LlmMessage = $"Function Error: No pending function call found for Message ID: {serviceObj.MessageID}\n\n";

            // Process the LLM output if it's the primary LLM
            if (_isPrimaryLlm || _isSystemLlm) _responseProcessor.ProcessLLMOutputError(responseServiceObj);

            _logger.LogWarning($"No pending function call found for Message ID: {serviceObj.MessageID}");
        }


        return false; // Indicates that the function call response could not be fully handled
    }

    private async Task HandleFunctionCallAsync(LLMServiceObj serviceObj, ToolCall fnCall, LLMServiceObj responseServiceObj, ChatMessage assistantChatMessage)
    {
        var fn = fnCall.FunctionCall;

        if (fn == null || fnCall.Id == null)
        {
            throw new Exception($" {_serviceID} Assistant OpenAI Error : Api call returned a Function with no Id");
        }
        string functionName = fn?.Name ?? "N/A";


        serviceObj.FunctionCallId = fnCall.Id;
        serviceObj.FunctionName = functionName;


        _logger.LogInformation($"Function call detected: {functionName}");

        var json = JsonSerializer.Serialize(fn!.ParseArguments());
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

        responseServiceObj.LlmMessage = "<Function Call:> " + functionName + " " + json + "\n";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
        // This is disabled until I find out how to set this without confusing chatgpt
        //assistantChatMessage.Content = $"Please wait I am calling the function {functionName}. Some functions take a long time to complete so please be patient...";
    }

    private async Task ProcessAssistantMessageAsync(ChatChoiceResponse choice, LLMServiceObj responseServiceObj, ChatMessage assistantChatMessage, List<ChatMessage> messageHistory, List<ChatMessage> history, LLMServiceObj serviceObj)
    {
        var responseChoiceStr = choice.Message.Content ?? "";
        _logger.LogInformation($"Assistant output : {responseChoiceStr}");

        if (choice.FinishReason == "stop")
        {
            assistantChatMessage.Content = responseChoiceStr;
            responseServiceObj.IsFunctionCallResponse = false;
            responseServiceObj.LlmMessage = "<Assistant:> " + responseChoiceStr + "\n\n";
            if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOuputInChunks(responseServiceObj);
            else
            {
                if (!_isSystemLlm) responseServiceObj.IsFunctionCallResponse = true;
                responseServiceObj.LlmMessage = responseChoiceStr;
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }

            messageHistory.Add(assistantChatMessage);

        }

        responseServiceObj.LlmMessage = "<end-of-line>";
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
                var firstMessage = history[0];
                if (firstMessage.Role == "user")
                {
                    // Remove the user message
                    history.RemoveAt(0);

                    // Remove the corresponding assistant response, which could be a regular response or a tool call
                    if (history.Count > 0 && history[0].Role == "assistant")
                    {
                        var assistantMessage = history[0];
                        history.RemoveAt(0); // Remove the assistant response or tool call

                        // If the assistant message is a tool call, remove all tool responses associated with it
                        if (assistantMessage.ToolCalls != null && assistantMessage.ToolCalls.Any())
                        {
                            foreach (var toolCall in assistantMessage.ToolCalls)
                            {
                                history.RemoveAll(m => m.ToolCallId == toolCall.Id);
                            }
                        }
                    }
                }
                else if (firstMessage.ToolCalls != null && firstMessage.ToolCalls.Any())
                {
                    // The first message is an assistant tool call, remove it and all associated responses
                    history.RemoveAt(0); // Remove the assistant tool call itself

                    foreach (var toolCall in firstMessage.ToolCalls)
                    {
                        history.RemoveAll(m => m.ToolCallId == toolCall.Id);
                    }
                }
                else
                {
                    // If the first message is anything else (e.g., an orphaned assistant response), remove it to maintain consistency
                    history.RemoveAt(0);
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


using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils;
using NetworkMonitor.Coordinator;

namespace NetworkMonitor.LLM.Services;

public class OpenAIRunner : ILLMRunner
{
    private ILogger _logger;
    private ILLMResponseProcessor _responseProcessor;
    private OpenAIService _openAiService; // Interface to interact with OpenAI

    private SemaphoreSlim _openAIRunnerSemaphore;
    private List<ChatMessage> _history;
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionCalls = new ConcurrentDictionary<string, ChatMessage>();
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionResponses = new ConcurrentDictionary<string, ChatMessage>();
    // Add these private fields to your OpenAIRunner class
    private readonly ConcurrentDictionary<string, Dictionary<string, string>> _toolCallIdMaps
    = new(StringComparer.Ordinal);

    private string _type = "TurboLLM";

    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isPrimaryLlm;
    private bool _isSystemLlm;
    private bool _isStream = false;
    private bool _isEnabled = true;
    //private bool _isFuncCalled;
    private readonly string _serviceID;
    private readonly string _serviceAuthKey;
    private int _maxTokens = 32000;
    private int _responseTokens = 4000;
    private int _promptTokens = 28000;
    private int _systemPromptTokens = 0;
    private MLParams _mlParams;
    private int _llmLoad;
    private List<ChatMessage> _systemPrompt = new List<ChatMessage>
{
    new ChatMessage
    {
        Role = "system",
        Content = ""
    }
};

    public List<ChatMessage> SystemPrompt
    {
        get => _systemPrompt;
        set => _systemPrompt = value ?? new List<ChatMessage>(); // Optional: Handle null assignment
    }



    public bool IsStateReady { get => _isStateReady; }
    public bool IsStateStarting { get => _isStateStarting; }
    public bool IsStateFailed { get => _isStateFailed; }
    public bool IsEnabled { get => _isEnabled; }
    public event Action<int, string> LoadChanged;
    public event Func<string, LLMServiceObj, Task> OnUserMessage;
    public event Func<string, LLMServiceObj, Task> RemoveSavedSession;
    public event Func<LLMServiceObj, Task> SendHistory;
    public int LlmLoad { get => _llmLoad; set => _llmLoad = value; }
    private readonly ILLMApi _llmApi;
    private bool _useHF = false;
    private bool _createAudio = false;
    private bool _noThink = false;

    private IAudioGenerator _audioGenerator;
    private HashSet<string> _ignoreParameters => LLMConfigFactory.IgnoreParameters;

    public string Type { get => _type; set => _type = value; }

    private readonly Queue<(string? FunctionName, string? ArgumentsJson)> _recentFunctionCalls = new Queue<(string?, string?)>();
    private const int MaxRecentFunctionCalls = 5;
    private int _funcsInARow = 0;
    private string? _lastChatAgentLocation;
    private static readonly Regex AgentLocationRegex =
        new Regex(@"Agent with location\s+(?<location>.+?)\s+use this for the agent_location",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IQueryCoordinator _queryCoordinator;
    private readonly IToolsBuilderFactory _toolsBuilderFactory;

#pragma warning disable CS8618
    public OpenAIRunner(ILogger<OpenAIRunner> logger, ILLMResponseProcessor responseProcessor, OpenAIService openAiService, SystemParams systemParams, MLParams mlParams, LLMServiceObj serviceObj, SemaphoreSlim? openAIRunnerSemaphore, IAudioGenerator audioGenerator, bool useHF, List<ChatMessage> history, IQueryCoordinator queryCoordinator, IToolsBuilderFactory toolsBuilderFactory)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _openAiService = openAiService;
        _openAIRunnerSemaphore = new SemaphoreSlim(1);
        _serviceID = systemParams.ServiceID!;
        _serviceAuthKey = systemParams.ServiceAuthKey!;
        _mlParams = mlParams;
        bool enableAgentFlow = _mlParams.EnableAgentFlow;
        _noThink = _mlParams.LlmNoThink;
        _history = history;
        _queryCoordinator = queryCoordinator;
        _toolsBuilderFactory = toolsBuilderFactory;

        string toolsId = serviceObj.ToolsDefinitionId ?? _serviceID;
        _logger.LogInformation($"Building tools for {toolsId} ");

        IToolsBuilder toolsBuilder = _toolsBuilderFactory.Create(
    toolsId,
    serviceObj.JsonToolsBuilderSpec,
    enableAgentFlow
);

        _useHF = useHF;
        _type = _useHF ? "HugLLM" : "TurboLLM";
        string llmProvider = _mlParams.LlmProvider.ToString();
        if (useHF) llmProvider = "HuggingFace";

        // Build the ILLMApi via the factory
        var llmApiFactory = new LLMApiFactory();
        _llmApi = llmApiFactory.CreateApi(
            _logger,
            _mlParams,
            toolsBuilder,
            _serviceID,
            _responseProcessor,
            systemParams,
            llmProvider,
            openAiService
        );
        string accountType = "Default";
        if (!string.IsNullOrEmpty(serviceObj.UserInfo.AccountType)) accountType = serviceObj.UserInfo.AccountType;
        _maxTokens = AccountTypeFactory.GetAccountTypeByName(accountType).ContextSize;
        if (_maxTokens > _mlParams.LlmOpenAICtxSize) _maxTokens = _mlParams.LlmOpenAICtxSize;
        _responseTokens = _maxTokens / _mlParams.LlmCtxRatio;
        _promptTokens = _maxTokens - _responseTokens;
        _audioGenerator = audioGenerator;


    }
#pragma warning restore CS8618 
    public Task StartProcess(LLMServiceObj serviceObj)
    {
        _isStateStarting = true;
        _isStateReady = false;
        _responseProcessor.IsManagedMultiFunc = true;
        if (_history.Count == 0)
        {
            _lastChatAgentLocation = NormalizeAgentLocation(serviceObj.ChatAgentLocation);
            _logger.LogInformation(
                "Agent location init (no history): {Location}",
                _lastChatAgentLocation ?? "<empty>");
        }
        else
        {
            _lastChatAgentLocation = GetLastAgentLocationFromHistory(_history);
            _logger.LogInformation(
                "Agent location init (from history): {Location}",
                _lastChatAgentLocation ?? "<empty>");
        }


        var systemPrompt = _llmApi.GetSystemPrompt(serviceObj.GetClientStartTime().ToString("yyyy-MM-ddTHH:mm:ss"), serviceObj, _noThink);

        _systemPromptTokens = CalculateTokens(systemPrompt);
        if (_history.Count == 0)
        {
            _history.AddRange(systemPrompt);
        }
        else
        {
            var resumeSystemPrompt = _llmApi.GetResumeSystemPrompt(serviceObj.GetClientStartTime().ToString("yyyy-MM-ddTHH:mm:ss"), serviceObj);

            /* // Remove the first 'systemPrompt.Count' items, if there are enough elements
             int removeCount = Math.Min(systemPrompt.Count, _history.Count);
             _history.RemoveRange(0, removeCount);

             // Insert the new system prompt at the beginning
             _history.InsertRange(0, resumeSystemPrompt);*/
            //Now we just add a system prompt with resume information
            _history.AddRange(resumeSystemPrompt);
        }
        _logger.LogInformation($"Started {_type} {_serviceID} Assistant with session id {serviceObj.SessionId} at {serviceObj.GetClientStartTime()}. with CTX size {_maxTokens} and Response tokens {_responseTokens}");

        _isStateStarting = false;
        _isStateReady = true;
        _isStateFailed = false;
        return Task.CompletedTask;
    }


    public Task RemoveProcess(string sessionId)
    {
        _isStateReady = false;
        _isStateReady = true;
        _isStateFailed = true;
        _logger.LogInformation($" Stopped {_type} {_serviceID} Assistant with session {sessionId}.  History has {_history.Count} messages.");
        return Task.CompletedTask;
    }


    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
        _isStateReady = false;

        var responseServiceObj = new LLMServiceObj(serviceObj);
        responseServiceObj.TokensUsed = 0;
        var assistantChatMessage = ChatMessage.FromAssistant("");
        bool isFuncMessage = false;

        if (serviceObj.UserInput.StartsWith("<|REMOVE_SAVED_SESSION|>"))
        {
            string fullSessionId = serviceObj.UserInput.Replace("<|REMOVE_SAVED_SESSION|>", string.Empty).Trim();
            if (!string.IsNullOrEmpty(fullSessionId) && RemoveSavedSession != null)
            {

                await RemoveSavedSession.Invoke(fullSessionId, serviceObj);

                _logger.LogInformation($"Success: Removed saved sessionId {fullSessionId}");
            }
            else
            {
                _logger.LogWarning("Warning: Empty or invalid session ID after removing prefix.");
            }
            return;
        }
        if (serviceObj.UserInput == "<|REPLAY_HISTORY|>")
        {
            await ReplayHistory(serviceObj.SessionId);
            if (SendHistory != null) await SendHistory.Invoke(serviceObj);
            _logger.LogInformation($" Replayed history for sessionId {serviceObj.SessionId}");
            return;
        }
        if (serviceObj.UserInput.StartsWith("<|GET_HISTORY_DISPLAY|>", StringComparison.Ordinal))
        {
            var requestedServiceId = serviceObj.UserInput
                .Substring("<|GET_HISTORY_DISPLAY|>".Length)
                .Trim();
            if (!string.IsNullOrWhiteSpace(requestedServiceId))
            {
                serviceObj.HistoryServiceId = requestedServiceId;
            }
            if (SendHistory != null) await SendHistory.Invoke(serviceObj);
            _logger.LogInformation($" Sent history display names for serviceId {serviceObj.HistoryServiceId ?? "default"}");
            return;
        }
        if (serviceObj.UserInput == "<|STOP_AUDIO|>")
        {
            _createAudio = false;
            _logger.LogInformation(" Stopping Create Audio");
            return;
        }
        if (serviceObj.UserInput == "<|START_AUDIO|>")
        {
            _createAudio = true;
            _logger.LogInformation(" Starting Create Audio");
            return;
        }

        _isPrimaryLlm = serviceObj.IsPrimaryLlm;
        _isSystemLlm = serviceObj.IsSystemLlm;

        /*if (serviceObj.IsFunctionStillRunning && _isPrimaryLlm)
        {
            //TODO work out how to use function still running messages
            _logger.LogInformation("Ignoring FunctionStillRunning message for non PrimaryLLM.");
            return;
        }*/

        _logger.LogInformation($"\nFrom FunctionState : {serviceObj.GetFunctionStateString()}\n\nReceived INPUT -> \n\n {serviceObj.UserInput} \n\n");


        try
        {
            LoadChanged?.Invoke(1, _type);
            await _openAIRunnerSemaphore.WaitAsync();

            // Retrieve or initialize the conversation history
            var localHistory = new List<ChatMessage>();

            ChatMessage chatMessage;
            if (serviceObj.IsFunctionCallStatus)
            {
                localHistory = HandleFunctionCallStatus(serviceObj);
                if (localHistory.Count > 0) isFuncMessage = true;
                else return;

            }
            else if (serviceObj.IsFunctionCallResponse)
            {
                localHistory = await HandleFunctionCallResponse(serviceObj, responseServiceObj);
                if (localHistory.Count > 0)
                {
                    isFuncMessage = true;
                    if (_mlParams.AddSystemRag) await _queryCoordinator.AddSystemRag(serviceObj.MessageID, localHistory);
                }
                else return;
            }
            else
            {
                var queryIndexRequest = new QueryIndexRequest
                {
                    IndexName = _mlParams.OpenSearchDefaultIndex,
                    QueryText = serviceObj.UserInput,
                    VectorSearchMode = _mlParams.VectorSearchMode,
                    MessageID = serviceObj.MessageID,
                    AppID = _serviceID,
                    AuthKey = _serviceAuthKey,
                    RoutingKey = "",
                    LLMRunnerType = serviceObj.LLMRunnerType,
                    ResponseExchange = $"{_serviceID.ToLowerInvariant()}QueryIndexResult"
                };
                if (_mlParams.AddSystemRag) _ = _queryCoordinator.ExecuteQueryAsync(queryIndexRequest);


                AddAgentLocationChangeMessage(localHistory, serviceObj);
                chatMessage = ChatMessage.FromUser(serviceObj.UserInput);

                responseServiceObj.LlmMessage = "<User:> " + serviceObj.UserInput + "\n\n";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                localHistory.Add(chatMessage);
                isFuncMessage = false;
            }

            TruncateTokens(_history, serviceObj);
            var currentHistory = new List<ChatMessage>(_history.Concat(localHistory));

            var completionSuccessResult = await _llmApi.CreateCompletionAsync(currentHistory, _responseTokens, serviceObj);
            var completionResult = completionSuccessResult.Response;
            var completionSuccess = completionSuccessResult.Success;

            if (completionSuccess)
            {
                ChatChoiceResponse choice = completionResult.Choices.First();
                if (choice.Message.ToolCalls != null && choice.Message.ToolCalls.Any())
                {
                    await HandleFunctionProcessing(serviceObj, choice.Message, localHistory, responseServiceObj, assistantChatMessage, isFuncMessage);
                }
                else
                {
                    await ProcessAssistantMessageAsync(choice, responseServiceObj, assistantChatMessage, localHistory, _history, serviceObj);
                }

                int tokensUsed = completionResult.Usage.TotalTokens;
                _logger.LogInformation($"TOKENS USED {tokensUsed}");
                if (!_useHF)
                {
                    var usage = completionResult.Usage;
                    int prompt = usage?.PromptTokens ?? 0;
                    int completion = usage?.CompletionTokens ?? 0;
                    int cached = usage?.PromptTokensDetails?.CachedTokens ?? 0;

                    // Guards
                    cached = Math.Min(cached, prompt);
                    var d = Math.Clamp(_mlParams.PromptCacheDiscountFraction, 0m, 1m); // 0..1
                    var k = _mlParams.CompletionCostMultiplier;
                    if (k < 1m) k = 1m;

                    // Billable prompt tokens = non-cached + discounted-cached
                    decimal billedPrompt = (prompt - cached) + (cached * (1m - d));

                    // Billable completion tokens = completion * multiplier
                    decimal billedCompletion = completion * k;

                    // Adjusted “cost-weighted tokens”
                    int adjusted = (int)Math.Round(billedPrompt + billedCompletion, MidpointRounding.AwayFromZero);
                    responseServiceObj.TokensUsed = adjusted;

                    _logger.LogInformation(
                      $"Usage raw: total={usage?.TotalTokens}, prompt={prompt}, completion={completion}, cached={cached}. " +
                      $"Pricing: cacheDiscount={d:P0}, completionX={k}. " +
                      $"Billed: prompt={billedPrompt}, completion={billedCompletion}, adjusted={adjusted}");

                }

            }
            else
            {
                if (completionResult.Error != null)
                {
                    await HandleOpenAIError(serviceObj, completionResult?.Error?.Message ?? "", localHistory, _history);
                    localHistory = new List<ChatMessage>();
                }
            }

            if (localHistory.Count > 0)
            {
                if (_mlParams.AddSystemRag) _queryCoordinator.RemoveSystemRag(localHistory);

                _history.AddRange(localHistory);
                await _responseProcessor.UpdateTokensUsed(responseServiceObj);
                int wordLimit = 5;
                string truncatedUserInput = string.Join(" ", serviceObj.UserInput.Split(' ').Take(wordLimit));
                if (OnUserMessage != null) await OnUserMessage.Invoke(truncatedUserInput, serviceObj);
            }

        }
        catch (OperationCanceledException oce)
        {
            _logger.LogWarning(oce, "Request cancelled for MessageID {MessageID}", serviceObj.MessageID);
            await NotifyUserErrorAsync(serviceObj,
                "That request was cancelled before it completed.", oce, detailed: false);
        }
        catch (TimeoutException te)
        {
            _logger.LogError(te, "Timeout in SendInputAndGetResponse for MessageID {MessageID}", serviceObj.MessageID);
            await NotifyUserErrorAsync(serviceObj,
                "Sorry — the request timed out. Please try again or shorten your last message.", te, detailed: false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception in SendInputAndGetResponse for MessageID {MessageID}", serviceObj.MessageID);
            await NotifyUserErrorAsync(serviceObj,
                "I hit an unexpected error and stopped this request. The issue was logged, and you can continue with a new message.",
                ex, detailed: false /* or _mlParams.ExposeInternalErrors */);
        }
        finally
        {
            try { _openAIRunnerSemaphore.Release(); } catch { /* best effort */ }
            _isStateReady = true;
            LoadChanged?.Invoke(-1, _type);
        }

    }

    private List<ChatMessage> HandleFunctionCallStatus(LLMServiceObj serviceObj)
    {
        var localHistory = new List<ChatMessage>();
        if (serviceObj.IsFunctionCallResponse == false) return localHistory;

        // if (!_useHF)
        //{
        var fakeFunctionCallId = StringUtils.NewToolCallId();
        var fakeFunctionCallMessage = ChatMessage.FromAssistant("");
        fakeFunctionCallMessage.ToolCalls = new List<ToolCall>()
                    {
                        new ToolCall
                            {
                                Type = "function",
                                Id = fakeFunctionCallId,
                                FunctionCall = new FunctionCall
                                {
                                    Name = "function_status_with_message_id",
                                    Arguments = $"{{\"message_id\":\"{serviceObj.RootMessageID}\"}}"
                                }
                            }
                    };

        localHistory.Add(fakeFunctionCallMessage);

        // Create a fake function response as if the tool returned a result
        var fakeFunctionResponseMessage = ChatMessage.FromTool(serviceObj.UserInput, fakeFunctionCallId);
        fakeFunctionResponseMessage.Role = "tool";
        fakeFunctionResponseMessage.Name = "function_status_with_message_id";
        fakeFunctionResponseMessage.Content = _llmApi.WrapFunctionResponse(serviceObj.FunctionName, serviceObj.UserInput) + "\n";
        // Add the fake function response to the message history
        localHistory.Add(fakeFunctionResponseMessage);
        /*}
        else
        {
            var systemMessage = ChatMessage.FromAssistant(serviceObj.UserInput);
            localHistory.Add(systemMessage);
        }*/
        return localHistory;
    }

    private void AddAgentLocationChangeMessage(List<ChatMessage> localHistory, LLMServiceObj serviceObj)
    {
        if (!serviceObj.IsPrimaryLlm) return;
        var currentLocation = NormalizeAgentLocation(serviceObj.ChatAgentLocation);
        if (string.IsNullOrEmpty(currentLocation))
        {
            _logger.LogInformation("Agent location change skipped: empty current location.");
            return;
        }

        if (string.IsNullOrEmpty(_lastChatAgentLocation))
        {
            _lastChatAgentLocation = currentLocation;
            _logger.LogInformation(
                "Agent location init (first seen): {Location}",
                _lastChatAgentLocation);
            return;
        }

        if (string.Equals(currentLocation, _lastChatAgentLocation, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation(
                "Agent location unchanged: {Location}",
                _lastChatAgentLocation);
            return;
        }

        var previousLocation = _lastChatAgentLocation;
        _lastChatAgentLocation = currentLocation;
        _logger.LogInformation(
            "Agent location changed: {Previous} -> {Current}",
            previousLocation,
            currentLocation);

        var message =
            $"User changed agent location from {previousLocation} to {currentLocation}. " +
            $"Use {currentLocation} for agent_location when calling experts unless the user specifies another agent location.";
        localHistory.Insert(0, ChatMessage.FromSystem(message));
    }

    private static string? NormalizeAgentLocation(string? location)
    {
        if (string.IsNullOrWhiteSpace(location)) return null;
        return location.Trim();
    }

    private static string? GetLastAgentLocationFromHistory(IEnumerable<ChatMessage> history)
    {
        foreach (var message in history.Reverse())
        {
            if (!string.Equals(message.Role, "system", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.IsNullOrWhiteSpace(message.Content)) continue;

            var match = AgentLocationRegex.Match(message.Content);
            if (!match.Success) continue;

            var location = match.Groups["location"].Value.Trim();
            if (!string.IsNullOrEmpty(location)) return location;
        }

        return null;
    }


    private async Task<List<ChatMessage>> HandleFunctionCallResponse(
       LLMServiceObj serviceObj,
       LLMServiceObj responseServiceObj)
    {
        ChatMessage funcResponseChatMessage;
        var localHistory = new List<ChatMessage>();
        bool isComplete = false;

        _pendingFunctionCalls.TryGetValue(serviceObj.MessageID, out var funcCallChatMessage);

        // Resolve the function call id through the mapping if needed
        string effectiveFuncCallId = serviceObj.FunctionCallId;
        if (_toolCallIdMaps.TryGetValue(serviceObj.MessageID, out var idMap))
        {
            // If the response came back with an ORIGINAL id, translate to the copy’s id
            if (idMap.TryGetValue(serviceObj.FunctionCallId, out var mappedId))
            {
                effectiveFuncCallId = mappedId;
            }
        }

        if (funcCallChatMessage != null && funcCallChatMessage.ToolCalls?.Count > 0)
        {
            // Use effectiveFuncCallId instead of serviceObj.FunctionCallId
            if (_pendingFunctionResponses.TryGetValue(effectiveFuncCallId, out var existingFuncResponseChatMessage))
            {
                funcResponseChatMessage = existingFuncResponseChatMessage;
                funcResponseChatMessage.Content =
                    _llmApi.WrapFunctionResponse(serviceObj.FunctionName, serviceObj.UserInput) + "\n";
            }
            else
            {
                funcResponseChatMessage = ChatMessage.FromTool("", effectiveFuncCallId);
                funcResponseChatMessage.Role = "tool";
                funcResponseChatMessage.Name = serviceObj.FunctionName;
                funcResponseChatMessage.Content =
                    _llmApi.WrapFunctionResponse(serviceObj.FunctionName, serviceObj.UserInput) + "\n";

                _pendingFunctionResponses.TryAdd(effectiveFuncCallId, funcResponseChatMessage);
            }

            bool allResponsesReceived = funcCallChatMessage.ToolCalls
                .All(tc => _pendingFunctionResponses.ContainsKey(tc.Id!));

            if (allResponsesReceived)
            {
                localHistory.Add(funcCallChatMessage);
                int count = 0;
                foreach (var toolCall in funcCallChatMessage.ToolCalls)
                {
                    if (_pendingFunctionResponses.TryGetValue(toolCall.Id!, out var response))
                    {
                        responseServiceObj.LlmMessage = "<Function Response:> " + response.Content + "\n\n";
                        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                        localHistory.Add(response);
                        _pendingFunctionResponses.TryRemove(toolCall.Id!, out _);
                        count++;
                    }
                }

                if (count == funcCallChatMessage.ToolCalls.Count)
                {
                    isComplete = true;
                }
                else
                {
                    _logger.LogError($" Error : Function calls failed to return the correct number of responses for {serviceObj.MessageID}");
                }

                _pendingFunctionCalls.TryRemove(serviceObj.MessageID, out _);

                // Clean up the mapping too
                _toolCallIdMaps.TryRemove(serviceObj.MessageID, out _);

                responseServiceObj.LlmMessage = "</functioncall-complete>";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }
        }
        else if (serviceObj.IsFunctionCallStatus == false)
        {
            responseServiceObj.LlmMessage =
                $"Function Error: No pending function call found for Message ID: {serviceObj.MessageID}\n\n";

            if (_isPrimaryLlm || _isSystemLlm)
                await _responseProcessor.ProcessLLMOutputError(responseServiceObj);

            _logger.LogWarning($"No pending function call found for Message ID: {serviceObj.MessageID}");
        }

        if (isComplete) return localHistory;
        return new List<ChatMessage>();
    }
    // OpenAI-style: "call_" + 26-char base62

    private async Task HandleFunctionProcessing(LLMServiceObj serviceObj, ChatMessage choiceMessage, List<ChatMessage> localHistory, LLMServiceObj responseServiceObj, ChatMessage assistantChatMessage, bool isFuncMessage)
    {
        bool usePlaceHolder = true;

        if (choiceMessage == null) return;
        // Create a deep copy of the choiceMessage to avoid modifying the original
        // Map original tool_call_id -> copied tool_call_id
        var toolCallIdMap = new Dictionary<string, string>(StringComparer.Ordinal);
        // usePlaceHolder should be false if ANY tool call is one of these control functions
        var choiceMessageCopy = new ChatMessage(); ;
        if (choiceMessage.ToolCalls is { Count: > 0 } &&
            choiceMessage.ToolCalls.Any(tc =>
            {
                var name = tc.FunctionCall?.Name;
                return name == "function_status_with_message_id"
                    || name == "cancel_functions"
                    || name == "get_function_result";
            }))
        {
            usePlaceHolder = false;
            _logger.LogDebug("Function call is a control function; not using placeholder.");
        }
        else
        {
            choiceMessageCopy = new ChatMessage
            {
                Role = choiceMessage.Role,
                Content = choiceMessage.Content,
                ToolCalls = choiceMessage.ToolCalls?.Select(tc =>
                {
                    var oldId = tc.Id ?? string.Empty;
                    var newId = StringUtils.NewToolCallId();     // ← NEW id for the copy
                    if (!string.IsNullOrEmpty(oldId))
                        toolCallIdMap[oldId] = newId;

                    return new ToolCall
                    {
                        Id = newId,
                        Type = tc.Type,
                        FunctionCall = tc.FunctionCall != null
                            ? new FunctionCall
                            {
                                Name = "get_function_result",
                                Arguments = @"{{""message_id"": """ + serviceObj.MessageID + @""", ""function_name"": """ + tc.FunctionCall.Name + @"""}}"
                            }
                            : null
                    };
                }).ToList()
            };
            usePlaceHolder = true;
        }


        string messageIdStr = "";
        string messageIdJson = "";

        if (serviceObj.IsPrimaryLlm)
        {
            messageIdStr = $"using message_id {serviceObj.MessageID}";
            messageIdJson = " , \"message_id\" : \"" + serviceObj.MessageID + "\"";
        }

        string pluralCall = "call";
        string plural = "is";
        if (choiceMessage.ToolCalls != null && choiceMessage.ToolCalls.Count > 1) { plural = "are"; pluralCall = "calls"; }

        var toolResponces = new List<ChatMessage>();
        bool isDuplicateSet = false;
        bool isDuplicate = false;
        int duplicateCount = 0;
        if (choiceMessage!.ToolCalls != null)
        {
            foreach (ToolCall fnCall in choiceMessage.ToolCalls)
            {
                if (fnCall.FunctionCall != null)
                {
                    var funcName = fnCall.FunctionCall.Name;
                    var argumentsJson = fnCall.FunctionCall.Arguments;
                    var funcId = fnCall.Id;
                    await HandleFunctionCallAsync(serviceObj, fnCall, responseServiceObj, assistantChatMessage);
                    await Task.Delay(500);
                    string extraMessage = "";
                    if (serviceObj.IsPrimaryLlm) extraMessage = "There is no need to call function_status_with_message_id because the system is actively monitoring the status and you will be informed as soon as the function completes..\"";
                    var toolResponse = ChatMessage.FromTool("{\"message\" : \"The function call " + funcName + " is currently running. " + extraMessage + messageIdJson + "}", funcId!);
                    toolResponse.Role = "tool";
                    toolResponse.Name = funcName;
                    toolResponces.Add(toolResponse);

                    if (!isDuplicateSet) isDuplicate = _recentFunctionCalls.Any(f =>
                    f.FunctionName == funcName &&
                    f.ArgumentsJson == argumentsJson);

                    if (!isDuplicateSet && isDuplicate)
                    {
                        isDuplicateSet = true;
                        duplicateCount = _recentFunctionCalls.Count(f =>
                    f.FunctionName == funcName &&
                    f.ArgumentsJson == argumentsJson);
                    }
                    _recentFunctionCalls.Enqueue((funcName, argumentsJson));


                }
            }
        }

        if (usePlaceHolder)
        {
            _pendingFunctionCalls.TryAdd(serviceObj.MessageID, choiceMessageCopy);
            localHistory.Add(choiceMessage);
            localHistory.AddRange(toolResponces);
            var assistantResponse = ChatMessage.FromAssistant($"Function {pluralCall} {messageIdStr} {plural} running. I will inform you of the result when it completes");
            localHistory.Add(assistantResponse);
            _toolCallIdMaps[serviceObj.MessageID] = toolCallIdMap;

        }
        else
        {
            _pendingFunctionCalls.TryAdd(serviceObj.MessageID, choiceMessage);
        }

        int numDequeue = MaxRecentFunctionCalls;
        if (isDuplicate && duplicateCount > 1)
        {
            _logger.LogWarning($"Possible loop detected when calling the same function with the same parameters");
            var duplicateMessage = ChatMessage.FromSystem(
                $" You are possibly stuck in a loop. Take a summary of what you have been doing and give the user feedback before continuing. If the user wants to call the same function again that is ok. Just check first.");
            localHistory.Add(duplicateMessage);
            numDequeue = 0;
        }
        while (_recentFunctionCalls.Count > numDequeue)
        {
            _recentFunctionCalls.Dequeue(); // Maintain queue size
        }
        if (++_funcsInARow >= _mlParams.MaxFunctionCallsInARow)
        {
            _logger.LogWarning($"Possible loop detected when calling functions without user feedback");
            var duplicateMessage = ChatMessage.FromSystem(
                $"You have called {_funcsInARow} functions in a row without giving the user any feedback. Take a summary of what you have been doing and give the user feedback before continuing. If the user wants to continue that is ok. Just check first.");
            localHistory.Add(duplicateMessage);
            _funcsInARow = 0;
        }
        return;
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
        string json = "";
        bool isValidJson = true;
        try
        {
            json = JsonSerializer.Serialize(fn!.ParseArguments());
        }
        catch (JsonException e)
        {
            var (failed, returnJson) = AttemptJsonRepair(fn!, e);
            isValidJson = !failed;
            json = returnJson;
        }
        catch (Exception e)
        {
            isValidJson = false;
            string errorMessage = JsonSerializer.Serialize(e.Message);
            json = $"{{\"invalid_json_error\" : \"{errorMessage}\"}}";

        }
        if (!isValidJson) _logger.LogError($" Error : invalid json from model. Sending json error : {json}");

        responseServiceObj.UserInput = serviceObj.UserInput;
        responseServiceObj.LlmMessage = "</functioncall>";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);

        LLMServiceObj functionResponseServiceObj;
        if (isValidJson) functionResponseServiceObj = new LLMServiceObj(serviceObj, fs => fs.SetAsCall())
        {
            JsonFunction = json,
            FunctionName = functionName
        };
        else functionResponseServiceObj = new LLMServiceObj(serviceObj, fs => fs.SetAsCallError())
        {
            JsonFunction = json,
            FunctionName = functionName
        };

        _logger.LogInformation($" Sending json: {json}");

        await _responseProcessor.ProcessFunctionCall(functionResponseServiceObj);

        responseServiceObj.LlmMessage = "<Function Call:> " + functionName + " " + json + "\n";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
    }
    // ADD to OpenAIRunner class
    private async Task NotifyUserErrorAsync(LLMServiceObj serviceObj, string userFacing, Exception? ex = null, bool detailed = false)
    {
        try
        {
            var msg = new StringBuilder();
            msg.AppendLine($"⚠️ {userFacing}");
            msg.AppendLine();
            msg.AppendLine($"Session: {serviceObj.SessionId}");
            msg.AppendLine($"Message ID: {serviceObj.MessageID}");

            if (detailed && ex != null)
            {
                // Only include details if you want to surface internals
                msg.AppendLine();
                msg.AppendLine($"Details: {ex.GetType().Name}: {ex.Message}");
            }

            var resp = new LLMServiceObj(serviceObj, fs => fs.SetAsResponseErrorComplete())
            {
                LlmMessage = msg.ToString()
            };

            if (_isPrimaryLlm || _isSystemLlm)
                await _responseProcessor.ProcessLLMOutputError(resp);
            else
                await _responseProcessor.ProcessLLMOutput(resp);
        }
        catch (Exception notifyEx)
        {
            _logger.LogError(notifyEx, "Failed to notify user about an error.");
            // last-ditch: we tried.
        }
    }

    private (bool failed, string json) AttemptJsonRepair(FunctionCall fn, JsonException e)
    {
        try
        {
            if (fn == null) throw new Exception(" fn is null");
            string input = fn.Arguments ?? "";
            string field = e?.Path?.Replace("$.", "") ?? "";
            if (!_ignoreParameters.Contains(field))
            {
                _logger.LogInformation("\n\nrepair => " + field + " \n\n");

                string testJson = JsonRepair.RepairJson(input);
                fn.Arguments = testJson;
                string repairedJson = JsonSerializer.Serialize(fn!.ParseArguments());
                _logger.LogInformation("Invalid JSON repair successfully.");
                return (false, repairedJson);
            }
            else
            {
                _logger.LogWarning($"Skipped JSON repair for sensitive path: {field}.");
            }
        }
        catch (Exception repairEx)
        {
            _logger.LogError($"Error: Failed to repair JSON. Exception: {repairEx.Message}");
        }

        return (true, JsonSerializer.Serialize(new
        {
            invalid_json_error = e?.Message ?? "Json Exception error message missing",
            path = e?.Path ?? "",
            line_number = e?.LineNumber,
            byte_position_in_line = e?.BytePositionInLine,
            hint = $"Check the structure and format of the JSON data. Check the '{e?.Path}' parameter value."
        }));

    }

    private async Task ProcessAssistantMessageAsync(ChatChoiceResponse choice, LLMServiceObj responseServiceObj, ChatMessage assistantChatMessage, List<ChatMessage> localHistory, List<ChatMessage> history, LLMServiceObj serviceObj)
    {
        var responseChoiceStr = choice.Message.Content ?? "";
        _logger.LogInformation($"Assistant output : {responseChoiceStr}");

        if (choice.FinishReason == "stop")
        {
            if (!string.IsNullOrEmpty(_llmApi.Config.ThinkBeginToken) && !string.IsNullOrEmpty(_llmApi.Config.ThinkEndToken))
            {
                string beginToken = Regex.Escape(_llmApi.Config.ThinkBeginToken);
                string endToken = Regex.Escape(_llmApi.Config.ThinkEndToken);
                string pattern = $@"{beginToken}.*?{endToken}";

                responseChoiceStr = Regex.Replace(responseChoiceStr, pattern, "", RegexOptions.Singleline);
            }
            assistantChatMessage.Content = responseChoiceStr;

            responseServiceObj.SetAsNotCall();
            if (_isPrimaryLlm)
            {
                if (_createAudio)
                {
                    bool isFirstChunk = true;

                    await foreach (var audioUrl in _audioGenerator.StreamAudioInOrder(responseChoiceStr))
                    {
                        if (isFirstChunk)
                        {
                            responseServiceObj.LlmMessage = "<Assistant:>" + responseChoiceStr + "\n";
                            if (!_isStream) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                            isFirstChunk = false;
                        }

                        responseServiceObj.LlmMessage = $"</audio>{audioUrl}";
                        _logger.LogInformation(responseServiceObj.LlmMessage);
                        await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    }
                }

                else
                {
                    responseServiceObj.LlmMessage = "<Assistant:>" + responseChoiceStr + "\n";
                    if (!_isStream) await _responseProcessor.ProcessLLMOutputInChunks(responseServiceObj);

                }

            }
            else
            {
                if (!_isSystemLlm) responseServiceObj.SetAsResponseComplete();


                responseServiceObj.LlmMessage = responseChoiceStr;
                if (!_isStream) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }

            localHistory.Add(assistantChatMessage);

        }

        responseServiceObj.LlmMessage = "<end-of-line>";
        _funcsInARow = 0;
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);

    }



    private void TruncateTokens(List<ChatMessage> history, LLMServiceObj serviceObj)
    {
        if (history == null || history.Count == 0) return;

        // 1) How many head messages to keep intact?
        int headCount = Math.Max(1, _llmApi.SystemPromptCount); // includes system + n-shot
        if (history.Count <= headCount) return;

        // 2) Split head and tail
        var head = history.Take(headCount).ToList();          // pinned, stable
        var tail = history.Skip(headCount).ToList();          // prune from here

        // 3) Compute budgets
        int headTokens = CalculateTokens(head);
        int maxPrompt = _promptTokens;                        // full budget available to messages
        int tailBudget = Math.Max(0, maxPrompt - headTokens); // how many tokens we can spend on tail

        // 4) If tail already fits, early-out
        int tailTokens = CalculateTokens(tail);
        if (tailTokens <= tailBudget) return;

        // 5) Trim from the OLDEST tail messages forward
        //    while keeping tool-call integrity
        //    (Remove in blocks and re-check token count each step)
        while (tail.Count > 0 && tailTokens > tailBudget)
        {
            // If the oldest is an assistant tool-call message, remove it + its tool responses
            var first = tail[0];
            if (first.ToolCalls != null && first.ToolCalls.Any())
            {
                // remove matching tool responses in the tail
                var toolIds = first.ToolCalls.Where(tc => tc.Id != null).Select(tc => tc.Id!).ToHashSet();
                tail.RemoveAt(0);
                tail.RemoveAll(m => m.Role == "tool" && m.ToolCallId != null && toolIds.Contains(m.ToolCallId));
            }
            else
            {
                // If it's a tool message but its assistant caller isn't in tail/head anymore,
                // just drop it (orphan cleanup)
                if (first.Role == "tool")
                {
                    tail.RemoveAt(0);
                }
                else
                {
                    // Otherwise drop a single message (oldest)
                    tail.RemoveAt(0);
                }
            }

            // Also clean up any remaining orphan tool responses
            RemoveOrphanToolResponses(serviceObj.SessionId, tail);

            tailTokens = CalculateTokens(tail);
        }

        // 6) Rebuild history: head + trimmed tail
        history.Clear();
        history.AddRange(head);
        history.AddRange(tail);
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
    private async Task HandleOpenAIError(LLMServiceObj serviceObj, string errorMessage, List<ChatMessage> localHistory, List<ChatMessage> sessionHistory)
    {
        string extraMessage = "";
        // Check if it’s the known “tool_calls did not have response messages” error

        ChatMessageLogger.LogChatMessages(_logger, sessionHistory, "Chat history before input");
        ChatMessageLogger.LogChatMessages(_logger, localHistory, "Attepted addition to chat history");

        if (errorMessage.Contains("did not have response messages") || errorMessage.Contains("messages with role"))
        {
            // Attempt to remove the incomplete tool call from memory
            RemoveUnansweredToolCalls(serviceObj.SessionId, sessionHistory);
            RemoveOrphanToolResponses(serviceObj.SessionId, sessionHistory);
            extraMessage = " A tool call was removed. ";
        }


        // Optionally send user a friendly error
        var responseObj = new LLMServiceObj(serviceObj, fs => fs.SetAsResponseErrorComplete())
        {
            LlmMessage = $"I encountered an error when calling {_type}.{extraMessage}\nError detail: {errorMessage}\n",
        };
        // If this is the “primary” or “system” LLM, do
        if (serviceObj.IsPrimaryLlm || serviceObj.IsSystemLlm) await _responseProcessor.ProcessLLMOutputError(responseObj);
        _logger.LogError($" {_serviceID} {responseObj.LlmMessage}");
    }
    private void RemoveUnansweredToolCalls(string sessionId, List<ChatMessage> sessionHistory)
    {
        // HF model does not use tool calls so they can be left in the history as they are.
        if (_useHF) return;

        if (sessionHistory == null || sessionHistory.Count == 0)
        {
            _logger.LogWarning($"No history found for session {sessionId} to remove unanswered tool calls.");
            return;
        }

        // Create a copy of the original history to log later if changes are made
        var originalHistory = new List<ChatMessage>(sessionHistory);

        bool foundUnansweredCalls = false;

        // Find assistant messages that contain tool calls
        var toolCallMessages = sessionHistory
            .Where(m => m.Role == "assistant"
                        && m.ToolCalls != null
                        && m.ToolCalls.Any())
            .ToList();

        // For each assistant message with tool calls,
        // check if all tool calls have a matching tool response
        foreach (var assistantMsg in toolCallMessages)
        {
            bool anyCallUnanswered = false;

            // Collect all the toolCallIds so we can remove them if incomplete
            var allToolCallIds = assistantMsg.ToolCalls!.Select(t => t.Id).Where(id => id != null).ToList();

            // If there is a single tool call that does not have a matching tool response, 
            // we consider this entire assistant message as "incomplete".
            foreach (var tCall in assistantMsg.ToolCalls!)
            {
                if (string.IsNullOrEmpty(tCall.Id))
                {
                    // If for some reason we have no ID on the tool call, treat it as unanswered
                    anyCallUnanswered = true;
                    _logger.LogInformation("Unanswered tool call detected: Missing tool call ID.");
                    break;
                }

                // See if any "tool" role message with the same tool_call_id exists
                var matchingToolResponse = sessionHistory.FirstOrDefault(
                    m => m.Role == "tool" && m.ToolCallId == tCall.Id
                );

                if (matchingToolResponse == null)
                {
                    // We found a tool call with no corresponding response
                    anyCallUnanswered = true;
                    foundUnansweredCalls = true;
                    _logger.LogInformation($"Unanswered tool call detected: Function Name = {tCall.FunctionCall?.Name}, Arguments = {tCall.FunctionCall?.Arguments}");
                    break;
                }
            }

            // If there’s at least one missing tool response, remove the entire assistant 
            // message and all partial tool responses that did exist
            if (anyCallUnanswered)
            {
                // Remove the tool responses that have the same IDs as the assistant’s calls
                foreach (var callId in allToolCallIds)
                {
                    // We remove all tool messages with matching toolCallId to keep the chat fully consistent
                    sessionHistory.RemoveAll(m => m.Role == "tool" && m.ToolCallId == callId);
                }

                // Finally, remove the assistant message itself
                sessionHistory.Remove(assistantMsg);

                _logger.LogError($"Error: Assistant message removed due to missing tool response: {assistantMsg.Content}");
            }
        }

        // Log the original and updated history only if unanswered tool calls were found
        if (foundUnansweredCalls)
        {
            _logger.LogWarning("Some messages had incomplete tool calls and were removed.");
            ChatMessageLogger.LogChatMessages(_logger, sessionHistory, "Updated Chat Message History After Cleanup");
        }
    }
    /// <summary>
    /// Removes tool responses that have no corresponding assistant message (i.e. orphaned tool calls).
    /// </summary>
    private void RemoveOrphanToolResponses(string sessionId, List<ChatMessage> sessionHistory)
    {
        // If using a HuggingFace model, skip because we do not use tool calls there.
        if (_useHF) return;

        if (sessionHistory == null || sessionHistory.Count == 0)
        {
            _logger.LogWarning($"No history found for session {sessionId} to remove orphaned tool responses.");
            return;
        }

        // Gather all tool-call IDs that exist in assistant messages
        var assistantToolCallIds = sessionHistory
            .Where(m => m.Role == "assistant" && m.ToolCalls != null && m.ToolCalls.Any())
            .SelectMany(m => m.ToolCalls!.Select(tc => tc.Id))
            .Where(id => !string.IsNullOrEmpty(id))
            .ToHashSet();

        // Find all tool messages whose ToolCallId is missing or does not match any known assistant call ID
        var orphanToolResponses = sessionHistory
            .Where(m => m.Role == "tool" &&
                        (string.IsNullOrEmpty(m.ToolCallId) ||
                         !assistantToolCallIds.Contains(m.ToolCallId)))
            .ToList();

        if (!orphanToolResponses.Any())
            return;

        // Remove the orphaned tool messages
        foreach (var orphanToolMsg in orphanToolResponses)
        {
            sessionHistory.Remove(orphanToolMsg);
            _logger.LogWarning(
                $"Removed orphaned tool response: ToolCallId='{orphanToolMsg.ToolCallId}', Content='{orphanToolMsg.Content}'");
        }

        // Optionally log the updated chat messages after removal
        //ChatMessageLogger.LogChatMessages(_logger, sessionHistory, 
        //    "Updated Chat Message History After Removing Orphaned Tool Responses");
    }

    public Task StopRequest(string sessionId)
    {
        // TODO: Implement stop logic
        return Task.CompletedTask;
    }

    public async Task ReplayHistory(string sessionId)
    {


        _isStateReady = false;

        try
        {
            await _openAIRunnerSemaphore.WaitAsync();

            // Iterate through the history and replay each message
            foreach (var message in _history.Skip(_llmApi.SystemPromptCount))
            {
                var responseServiceObj = new LLMServiceObj
                {
                    SessionId = sessionId,
                    LlmMessage = "",
                    TokensUsed = 0
                };

                switch (message.Role)
                {
                    case "user":
                        responseServiceObj.LlmMessage = "<User:> " + message.Content + "\n\n";
                        await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                        break;

                    case "assistant":
                        if (message.ToolCalls != null && message.ToolCalls.Any())
                        {
                            // Handle tool calls
                            foreach (var toolCall in message.ToolCalls)
                            {
                                if (toolCall.FunctionCall != null)
                                {
                                    responseServiceObj.LlmMessage = $"<Function Call:> {toolCall.FunctionCall.Name} {toolCall.FunctionCall.Arguments}\n";
                                    await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                                }
                            }
                        }
                        else
                        {
                            // Handle assistant response
                            responseServiceObj.LlmMessage = "<Assistant:> " + message.Content + "\n";
                            await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                        }
                        break;

                    case "tool":
                        // Handle tool responses
                        responseServiceObj.LlmMessage = $"<Function Response:> {message.Content}\n\n";
                        await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                        break;

                    default:
                        _logger.LogWarning($"Unsupported message role: {message.Role}");
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error replaying history for session {sessionId}: {ex.Message}");
        }
        finally
        {
            _openAIRunnerSemaphore.Release();
            _isStateReady = true;
        }
    }

}

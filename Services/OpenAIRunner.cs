
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
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils;

namespace NetworkMonitor.LLM.Services;

public class OpenAIRunner : ILLMRunner
{
    private ILogger _logger;
    private ILLMResponseProcessor _responseProcessor;
    private OpenAIService _openAiService; // Interface to interact with OpenAI

    private ConcurrentDictionary<string, DateTime> _activeSessions;

    private SemaphoreSlim _openAIRunnerSemaphore;
    private ConcurrentDictionary<string, List<ChatMessage>> _sessionHistories = new ConcurrentDictionary<string, List<ChatMessage>>();

    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionCalls = new ConcurrentDictionary<string, ChatMessage>();
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionResponses = new ConcurrentDictionary<string, ChatMessage>();

    public string Type { get => "TurboLLM"; }
    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isPrimaryLlm;
    private bool _isSystemLlm;
    private bool _isEnabled = true;
    //private bool _isFuncCalled;
    private string _serviceID;
    private int _maxTokens = 2000;
    private int _responseTokens = 2000;
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
    public int LlmLoad { get => _llmLoad; set => _llmLoad = value; }
    private readonly ILLMApi _llmApi;
    private bool _useHF = false;
    private string _gptModel = "";
    private string _hFModelID = "";
    private string _hFKey = "";
    private string _hFUrl = "";
    private string _hfModel = "";
    private bool _createAudio = false;
    private IAudioGenerator _audioGenerator;
    private HashSet<string> _ignoreParameters => LLMConfigFactory.IgnoreParameters;

#pragma warning disable CS8618
    public OpenAIRunner(ILogger<OpenAIRunner> logger, ILLMResponseProcessor responseProcessor, OpenAIService openAiService, ISystemParamsHelper systemParamsHelper, LLMServiceObj serviceObj, SemaphoreSlim openAIRunnerSemaphore, IAudioGenerator audioGenerator)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _openAiService = openAiService;
        _openAIRunnerSemaphore = openAIRunnerSemaphore;
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _maxTokens = systemParamsHelper.GetMLParams().LlmOpenAICtxSize!;
        _responseTokens = systemParamsHelper.GetMLParams().LlmResponseTokens!;
        _hFModelID = systemParamsHelper.GetMLParams().LlmHFModelID!;
        _hFKey = systemParamsHelper.GetMLParams().LlmHFKey!;
        _hFUrl = systemParamsHelper.GetMLParams().LlmHFUrl!;
        _hfModel = systemParamsHelper.GetMLParams().LlmHFModelVersion!;
        _gptModel = systemParamsHelper.GetMLParams().LlmGptModel!;
        _useHF = systemParamsHelper.GetMLParams().LlmUseHF;
        IToolsBuilder? toolsBuilder = null;
        if (_serviceID == "monitor") toolsBuilder = new MonitorToolsBuilder(serviceObj.UserInfo);
        if (_serviceID == "cmdprocessor") toolsBuilder = new CmdProcessorToolsBuilder(serviceObj.UserInfo);
        if (_serviceID == "nmap") toolsBuilder = new NmapToolsBuilder();
        if (_serviceID == "meta") toolsBuilder = new MetaToolsBuilder();
        if (_serviceID == "search") toolsBuilder = new SearchToolsBuilder();

        if (_serviceID == "blogmonitor") toolsBuilder = new BlogMonitorToolsBuilder(serviceObj.UserInfo);
        if (_serviceID == "reportdata") toolsBuilder = new ReportDataToolsBuilder();
        if (toolsBuilder == null) toolsBuilder = new MonitorToolsBuilder(serviceObj.UserInfo);

        if (!_useHF)
        {
            _llmApi = new OpenAIApi(_logger, _openAiService, toolsBuilder, _gptModel);
        }
        else
        {
            _llmApi = new HuggingFaceApi(_logger, toolsBuilder, _hFUrl, _hFKey, _hFModelID, _hfModel);
        }
        _maxTokens = AccountTypeFactory.GetAccountTypeByName(serviceObj.UserInfo.AccountType!).ContextSize;
        _activeSessions = new ConcurrentDictionary<string, DateTime>();
        _sessionHistories = new ConcurrentDictionary<string, List<ChatMessage>>();
        _audioGenerator = audioGenerator;

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

        var systemPrompt = _llmApi.GetSystemPrompt(_activeSessions[serviceObj.SessionId].ToString("yyyy-MM-ddTHH:mm:ss"), serviceObj);
        _sessionHistories.GetOrAdd(serviceObj.SessionId, systemPrompt);

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
        bool isFuncMessage = false;

        if (!_activeSessions.ContainsKey(serviceObj.SessionId))
        {
            _isStateFailed = true;
            throw new Exception($"No TurboLLM {_serviceID} Assistants found for session {serviceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
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
            LoadChanged?.Invoke(1, Type);
            await _openAIRunnerSemaphore.WaitAsync();

            // Retrieve or initialize the conversation history
            var history = _sessionHistories[serviceObj.SessionId];
            var localHistory = new List<ChatMessage>();

            ChatMessage chatMessage;
            if (serviceObj.IsFunctionCallStatus)
            {
                localHistory = HandleFunctionCallStatus(serviceObj);
                if (localHistory.Count > 0) isFuncMessage = true;

            }
            else if (serviceObj.IsFunctionCallResponse)
            {
                localHistory = HandleFunctionCallResponse(serviceObj, responseServiceObj);
                if (localHistory.Count > 0) isFuncMessage = true;
            }
            else
            {
                chatMessage = ChatMessage.FromUser(serviceObj.UserInput);
                responseServiceObj.LlmMessage = "<User:> " + serviceObj.UserInput + "\n\n";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                localHistory.Add(chatMessage);
                isFuncMessage = false;
            }


            var currentHistory = new List<ChatMessage>(history.Concat(localHistory));
            var completionSuccessResult = await _llmApi.CreateCompletionAsync(currentHistory, _responseTokens);
            var completionResult = completionSuccessResult.Response;
            var completionSuccess = completionSuccessResult.Success;

            if (completionSuccess)
            {
                responseServiceObj.TokensUsed = completionResult.Usage.TotalTokens;
                if (completionResult.Usage != null && completionResult.Usage.PromptTokensDetails != null) _logger.LogInformation($"Cached Prompt Tokens {completionResult.Usage.PromptTokensDetails.CachedTokens}");
                ChatChoiceResponse choice = completionResult.Choices.First();
                if (choice.Message.ToolCalls != null && choice.Message.ToolCalls.Any())
                {
                    await HandleFunctionProcessing(serviceObj, choice.Message, localHistory, responseServiceObj, assistantChatMessage, isFuncMessage);
                }
                else
                {
                    await ProcessAssistantMessageAsync(choice, responseServiceObj, assistantChatMessage, localHistory, history, serviceObj);
                }


            }
            else
            {
                if (completionResult.Error != null)
                {
                    await HandleOpenAIError(serviceObj, completionResult.Error.Message, localHistory, history);
                    localHistory = new List<ChatMessage>();
                }
            }

            if (localHistory.Count > 0)
            {
                history.AddRange(localHistory);
                TruncateTokens(history, serviceObj);
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
            LoadChanged?.Invoke(-1, Type); // Increment load for this type

        }
    }

    private List<ChatMessage> HandleFunctionCallStatus(LLMServiceObj serviceObj)
    {
        var localHistory = new List<ChatMessage>();

        /*if (!_useHF)
        {
            var fakeFunctionCallId = "call_" + StringUtils.GetNanoid();
            var fakeFunctionCallMessage = ChatMessage.FromAssistant("");
            fakeFunctionCallMessage.ToolCalls = new List<ToolCall>()
                    {
                        new ToolCall
                            {
                                Type = "function",
                                Id = fakeFunctionCallId,
                                FunctionCall = new FunctionCall
                                {
                                    Name = "are_functions_running",
                                    Arguments = $"{{\"message_id\":\"{serviceObj.RootMessageID}\"}}"
                                }
                            }
                    };

            localHistory.Add(fakeFunctionCallMessage);

            // Create a fake function response as if the tool returned a result
            var fakeFunctionResponseMessage = ChatMessage.FromTool(serviceObj.UserInput, fakeFunctionCallId);
            fakeFunctionResponseMessage.Role = "tool";
            fakeFunctionResponseMessage.Name = "are_functions_running";

            // Add the fake function response to the message history
            localHistory.Add(fakeFunctionResponseMessage);
        }
        else*/
        {
            var systemMessage = ChatMessage.FromAssistant(serviceObj.UserInput);
            localHistory.Add(systemMessage);
        }
        return localHistory;
    }


    private List<ChatMessage> HandleFunctionCallResponse(LLMServiceObj serviceObj, LLMServiceObj responseServiceObj)
    {
        ChatMessage funcResponseChatMessage;
        var localHistory = new List<ChatMessage>();
        bool isComplete = false;
        // Check if there are any pending function calls associated with the current message
        _pendingFunctionCalls.TryGetValue(serviceObj.MessageID, out var funcCallChatMessage);
        if (funcCallChatMessage != null && funcCallChatMessage.ToolCalls != null && funcCallChatMessage.ToolCalls.Count > 0)
        {
            // Check if a response for the given FunctionCallId already exists in the dictionary
            if (_pendingFunctionResponses.TryGetValue(serviceObj.FunctionCallId, out var existingFuncResponseChatMessage))
            {
                // Update the existing response with the new content
                funcResponseChatMessage = existingFuncResponseChatMessage;
                funcResponseChatMessage.Content = _llmApi.WrapFunctionResponse(serviceObj.FunctionName, serviceObj.UserInput) + "\n";
            }
            else
            {
                // Create a new ChatMessage for the function response if it doesn't exist
                funcResponseChatMessage = ChatMessage.FromTool("", serviceObj.FunctionCallId);
                funcResponseChatMessage.Role = "tool";
                funcResponseChatMessage.Name = serviceObj.FunctionName;
                funcResponseChatMessage.Content = _llmApi.WrapFunctionResponse(serviceObj.FunctionName, serviceObj.UserInput) + "\n";


                // Add the new response to the dictionary
                _pendingFunctionResponses.TryAdd(serviceObj.FunctionCallId, funcResponseChatMessage);
            }


            responseServiceObj.LlmMessage = "<Function Response:> " + serviceObj.UserInput + "\n\n";

            // Process the LLM output if it's the primary LLM
            if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);

            bool allResponsesReceived = funcCallChatMessage.ToolCalls
                .All(tc => _pendingFunctionResponses.ContainsKey(tc.Id!));


            if (allResponsesReceived)
            {
                // Add the function call and responses to the message history only if its OpenAI. HF we have aleady added it
                if (!_useHF) localHistory.Add(funcCallChatMessage);
                int count = 0;
                foreach (var toolCall in funcCallChatMessage.ToolCalls)
                {
                    if (_pendingFunctionResponses.TryGetValue(toolCall.Id!, out var response))
                    {

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

                // Mark the function call as complete
                responseServiceObj.LlmMessage = "</functioncall-complete>";
                if (_isPrimaryLlm) _responseProcessor.ProcessLLMOutput(responseServiceObj);

            }
        }
        else if (serviceObj.IsFunctionCallStatus == false)
        {
            responseServiceObj.LlmMessage = $"Function Error: No pending function call found for Message ID: {serviceObj.MessageID}\n\n";

            // Process the LLM output if it's the primary LLM
            if (_isPrimaryLlm || _isSystemLlm) _responseProcessor.ProcessLLMOutputError(responseServiceObj);

            _logger.LogWarning($"No pending function call found for Message ID: {serviceObj.MessageID}");
        }
        if (isComplete) return localHistory;
        return new List<ChatMessage>();
    }

    private async Task HandleFunctionProcessing(LLMServiceObj serviceObj, ChatMessage choiceMessage, List<ChatMessage> localHistory, LLMServiceObj responseServiceObj, ChatMessage assistantChatMessage, bool isFuncMessage)
    {

        // Note we deal with HF modles assistant function call messages differently to OpenAi models.
        // OpenAI models need the assistant func calls to be followed by the respones. HF models don't
        // The _useHF parameter is used to construct the messages that are added to the history to deal with this difference
        if (!_useHF) choiceMessage.Content = $"The user previously requested \"{serviceObj.UserInput}\" . The function calls needed to answer this query have now completed. ";
        _pendingFunctionCalls.TryAdd(serviceObj.MessageID, choiceMessage);
        if (!_useHF)
        {
            // Replace the user message with the message_id, only for OpenAI modesl
            var placeholderUser = ChatMessage.FromUser($"{serviceObj.UserInput} : us message_id <|{serviceObj.MessageID}|> to track the function calls");
            localHistory.Add(placeholderUser);
            if (!isFuncMessage) localHistory.RemoveAt(0);
        }

        var assistantMessage = new StringBuilder($"I have called the following functions : ");
        foreach (ToolCall fnCall in choiceMessage.ToolCalls)
        {
            if (fnCall.FunctionCall != null)
            {
                var funcName = fnCall.FunctionCall.Name;
                var funcArgs = fnCall.FunctionCall.Arguments;
                assistantMessage.Append($" Name {funcName} Arguments {funcArgs} : ");
                // Handle the function call asynchronously and remove the placeholder when complete
                await HandleFunctionCallAsync(serviceObj, fnCall, responseServiceObj, assistantChatMessage);
                await Task.Delay(500);
            }
        }
        assistantMessage.Append($" using message_id {serviceObj.MessageID} . Please wait it may take some time to complete.");

        // OpenAI models we also add a assistant message with no func calls to the history.
        if (!_useHF) localHistory.Add(ChatMessage.FromAssistant(assistantMessage.ToString()));
        else localHistory.Add(choiceMessage);
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
            var (failed, returnJson) = AttemptJsonRepair(fn, e);
            isValidJson = !failed;
            json = returnJson;
        }
        catch (Exception e)
        {
            isValidJson = false;
            string errorMessage = JsonSerializer.Serialize(e.Message);
            json = $"{{\"invalid_json_error\" : \"{errorMessage}\"}}";

        }
        if (!isValidJson) _logger.LogError($" Error : invald json from model. Sending json error : {json}");

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
        // This is disabled until I find out how to set this without confusing chatgpt
        //assistantChatMessage.Content = $"Please wait I am calling the function {functionName}. Some functions take a long time to complete so please be patient...";
    }

    private (bool failed, string json) AttemptJsonRepair(FunctionCall fn, JsonException e)
    {
        try
        {
            string input = fn.Arguments;
            string field = e.Path.Replace("$.", "");
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
                _logger.LogWarning("Skipped JSON repair for sensitive path: source_code.");
            }
        }
        catch (Exception repairEx)
        {
            _logger.LogError($"Error: Failed to repair JSON. Exception: {repairEx.Message}");
        }

        return (true, JsonSerializer.Serialize(new
        {
            invalid_json_error = e.Message,
            path = e.Path,
            line_number = e.LineNumber,
            byte_position_in_line = e.BytePositionInLine,
            hint = $"Check the structure and format of the JSON data. Check the '{e.Path}' parameter value."
        }));

    }

    private async Task ProcessAssistantMessageAsync(ChatChoiceResponse choice, LLMServiceObj responseServiceObj, ChatMessage assistantChatMessage, List<ChatMessage> localHistory, List<ChatMessage> history, LLMServiceObj serviceObj)
    {
        var responseChoiceStr = choice.Message.Content ?? "";
        _logger.LogInformation($"Assistant output : {responseChoiceStr}");

        if (choice.FinishReason == "stop")
        {
            assistantChatMessage.Content = responseChoiceStr;
            responseServiceObj.SetAsNotCall();
            if (_isPrimaryLlm)
            {
                if (_createAudio)
                {
                    bool isFirstChunk = true;
                    var chunks = _audioGenerator.GetChunksFromText(responseChoiceStr, 500);
                    foreach (var chunk in chunks)
                    {
                        string audioFileUrl = await _audioGenerator.AudioForResponse(chunk);
                        if (isFirstChunk)
                        {
                            responseServiceObj.LlmMessage = responseChoiceStr + "\n";
                            await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                            isFirstChunk = false;
                        }

                        responseServiceObj.LlmMessage = $"</audio>{audioFileUrl}";
                        await _responseProcessor.ProcessLLMOutput(responseServiceObj);

                    }
                }
                else
                {
                    responseServiceObj.LlmMessage = responseChoiceStr + "\n";
                    await _responseProcessor.ProcessLLMOutputInChunks(responseServiceObj);

                }

            }
            else
            {
                if (!_isSystemLlm) responseServiceObj.SetAsResponseComplete();
                responseServiceObj.LlmMessage = responseChoiceStr;
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }

            localHistory.Add(assistantChatMessage);

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
                if (firstMessage.ToolCalls != null && firstMessage.ToolCalls.Any())
                {
                    foreach (var toolCall in firstMessage.ToolCalls)
                    {
                        history.RemoveAll(m => m.ToolCallId == toolCall.Id);
                    }
                }

                history.RemoveAt(0);

                // Recalculate tokens after removal
                tokenCount = CalculateTokens(history);
            }
            // Tidy up in case any tool calls have missing tool responses
            RemoveUnansweredToolCalls(serviceObj.SessionId, history);
            RemoveOrphanToolResponses(serviceObj.SessionId, history);

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
            LlmMessage = $"I encountered an error when calling TurboLLM.{extraMessage}\nError detail: {errorMessage}\n",
        };
        // If this is the “primary” or “system” LLM, do
        await _responseProcessor.ProcessLLMOutputError(responseObj);
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



}

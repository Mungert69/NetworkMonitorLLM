
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

    private SemaphoreSlim _openAIRunnerSemaphore;
    private List<ChatMessage> _history;
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionCalls = new ConcurrentDictionary<string, ChatMessage>();
    private ConcurrentDictionary<string, ChatMessage> _pendingFunctionResponses = new ConcurrentDictionary<string, ChatMessage>();
    private string _type = "TurboLLM";

    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isPrimaryLlm;
    private bool _isSystemLlm;
    private bool _isStream = false;
    private bool _isEnabled = true;
    //private bool _isFuncCalled;
    private string _serviceID;
    private int _maxTokens = 32000;
    private int _responseTokens = 4000;
    private int _promptTokens = 28000;
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

    private IAudioGenerator _audioGenerator;
    private HashSet<string> _ignoreParameters => LLMConfigFactory.IgnoreParameters;

    public string Type { get => _type; set => _type = value; }

#pragma warning disable CS8618
    public OpenAIRunner(ILogger<OpenAIRunner> logger, ILLMResponseProcessor responseProcessor, OpenAIService openAiService, ISystemParamsHelper systemParamsHelper, LLMServiceObj serviceObj, SemaphoreSlim openAIRunnerSemaphore, IAudioGenerator audioGenerator, bool useHF, List<ChatMessage> history)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _openAiService = openAiService;
        _openAIRunnerSemaphore = openAIRunnerSemaphore;
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _mlParams = systemParamsHelper.GetMLParams();
        _history = history;

        _useHF = useHF;
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
            _type = "TurboLLM";
            _llmApi = new OpenAIApi(_logger, _mlParams, toolsBuilder, _serviceID, _openAiService);
        }
        else
        {
            _type = "HugLLM";
            _isStream = _mlParams.IsStream;
            _llmApi = new HuggingFaceApi(_logger, _mlParams, toolsBuilder, _serviceID, _responseProcessor, _isStream);
        }
        string accountType = "Free";
        if (!string.IsNullOrEmpty(serviceObj.UserInfo.AccountType)) accountType = serviceObj.UserInfo.AccountType;
        _maxTokens = AccountTypeFactory.GetAccountTypeByName(accountType).ContextSize;
        if (_maxTokens > _mlParams.LlmOpenAICtxSize) _maxTokens = _mlParams.LlmOpenAICtxSize;
        _responseTokens = _maxTokens / _mlParams.LlmCtxRatio;
        _promptTokens = _maxTokens - _responseTokens;
        _audioGenerator = audioGenerator;


    }
#pragma warning restore CS8618
    public async Task StartProcess(LLMServiceObj serviceObj)
    {
        _isStateStarting = true;
        _isStateReady = false;
        _responseProcessor.IsManagedMultiFunc = true;

        var systemPrompt = _llmApi.GetSystemPrompt(serviceObj.GetClientStartTime().ToString("yyyy-MM-ddTHH:mm:ss"), serviceObj);

        if (_history.Count == 0)
        {
            _history.AddRange(systemPrompt);
        }
        else
        {
            // Remove the first 'systemPrompt.Count' items, if there are enough elements
            int removeCount = Math.Min(systemPrompt.Count, _history.Count);
            _history.RemoveRange(0, removeCount);

            // Insert the new system prompt at the beginning
            _history.InsertRange(0, systemPrompt);
        }

        _logger.LogInformation($"Started {_type} {_serviceID} Assistant with session id {serviceObj.SessionId} at {serviceObj.GetClientStartTime()}. with CTX size {_maxTokens} and Response tokens {_responseTokens}");

        _isStateStarting = false;
        _isStateReady = true;
        _isStateFailed = false;
    }


    public Task RemoveProcess(string sessionId)
    {
        _isStateReady = false;

        // DO something here 

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
            await SendHistory?.Invoke(serviceObj);
            _logger.LogInformation($" Replayed history for sessionId {serviceObj.SessionId}");
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


            var currentHistory = new List<ChatMessage>(_history.Concat(localHistory));
            var completionSuccessResult = await _llmApi.CreateCompletionAsync(currentHistory, _responseTokens, serviceObj);
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
                    await ProcessAssistantMessageAsync(choice, responseServiceObj, assistantChatMessage, localHistory, _history, serviceObj);
                }


            }
            else
            {
                if (completionResult.Error != null)
                {
                    await HandleOpenAIError(serviceObj, completionResult.Error.Message, localHistory, _history);
                    localHistory = new List<ChatMessage>();
                }
            }

            if (localHistory.Count > 0)
            {
                _history.AddRange(localHistory);
                TruncateTokens(_history, serviceObj);
                await _responseProcessor.UpdateTokensUsed(responseServiceObj);
                 int wordLimit = 5;
                string truncatedUserInput = string.Join(" ", serviceObj.UserInput.Split(' ').Take(wordLimit));
                await OnUserMessage?.Invoke(truncatedUserInput, serviceObj);              
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
            LoadChanged?.Invoke(-1, _type); // Increment load for this _type

        }
    }

    private List<ChatMessage> HandleFunctionCallStatus(LLMServiceObj serviceObj)
    {
        var localHistory = new List<ChatMessage>();
        if (serviceObj.IsFunctionCallResponse == false) return localHistory;

        // if (!_useHF)
        //{
        var fakeFunctionCallId = "call_" + StringUtils.GetNanoid();
        var fakeFunctionCallMessage = ChatMessage.FromAssistant("I have received an are_functions_running auto-check status update.");
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
                //if (!_useHF) 
                localHistory.Add(funcCallChatMessage);
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


        // Create a deep copy of the choiceMessage to avoid modifying the original
        var choiceMessageCopy = new ChatMessage
        {
            Role = choiceMessage.Role,
            Content = choiceMessage.Content,
            ToolCalls = choiceMessage.ToolCalls?.Select(tc => new ToolCall
            {
                Id = tc.Id,
                Type = tc.Type,
                FunctionCall = tc.FunctionCall != null ? new FunctionCall
                {
                    Name = tc.FunctionCall.Name,
                    Arguments = tc.FunctionCall.Arguments
                } : null
            }).ToList()
        };

        // Store the original message content
        string origMessage = choiceMessageCopy.Content;

        // Update the copy's content for the pending function call
        choiceMessageCopy.Content = $"The function call with message_id {serviceObj.MessageID} has now completed.";
        _pendingFunctionCalls.TryAdd(serviceObj.MessageID, choiceMessageCopy);
        //TODO make a copy of the choiceMesage and use that instead 
        var toolResponces = new List<ChatMessage>();
        foreach (ToolCall fnCall in choiceMessage.ToolCalls)
        {
            if (fnCall.FunctionCall != null)
            {
                var funcName = fnCall.FunctionCall.Name;
                var funcArgs = fnCall.FunctionCall.Arguments;
                var funcId = fnCall.Id;
                await HandleFunctionCallAsync(serviceObj, fnCall, responseServiceObj, assistantChatMessage);
                await Task.Delay(500);
                var toolResponse = ChatMessage.FromTool($"The function {funcName} has been called, waiting for the result. DO NOT call are_functions_running unless the user asks you to.", funcId);
                toolResponse.Role = "tool";
                toolResponse.Name = funcName;
                toolResponces.Add(toolResponse);
            }
        }
        choiceMessage.Content = $"{origMessage} . I have called the functions using message_id {serviceObj.MessageID} . Please wait it may take some time to complete.";

        // OpenAI models we also add a assistant message with no func calls to the history.
        localHistory.Add(choiceMessage);
        localHistory.AddRange(toolResponces);

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
                _logger.LogWarning($"Skipped JSON repair for sensitive path: {field}.");
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
                            responseServiceObj.LlmMessage = "<Assistant:>" + responseChoiceStr + "\n";
                            if (!_isStream) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                            isFirstChunk = false;
                        }

                        responseServiceObj.LlmMessage = $"</audio>{audioFileUrl}";
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
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
    }




    private void TruncateTokens(List<ChatMessage> history, LLMServiceObj serviceObj)
    {
        int tokenCount = CalculateTokens(history);
        _logger.LogInformation($"History Token count: {tokenCount}");

        if (tokenCount > _promptTokens)
        {
            _logger.LogInformation($"Token count ({tokenCount}) exceeded the limit, truncating history.");

            // Keep the first system message intact
            var systemMessage = history.First();
            history = history.Skip(1).ToList();

            // Remove messages until the token count is under the limit
            while (tokenCount > _promptTokens)
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
            LlmMessage = $"I encountered an error when calling {_type}.{extraMessage}\nError detail: {errorMessage}\n",
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

    public async Task ReplayHistory(string sessionId)
    {


        _isStateReady = false;

        try
        {
            await _openAIRunnerSemaphore.WaitAsync();

            // Iterate through the history and replay each message
            foreach (var message in _history)
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

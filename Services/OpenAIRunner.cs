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

    public async Task StartProcess(string sessionId, DateTime currentTime)
    {
        if (!_activeSessions.TryAdd(sessionId, currentTime))
        {
            throw new InvalidOperationException("Session already exists.");
        }

        _logger.LogInformation($"Started session {sessionId} at {currentTime}.");
        // Here, you might want to send an initial message or perform other setup tasks.
    }

    public async Task RemoveProcess(string sessionId)
    {
        if (!_activeSessions.TryRemove(sessionId, out var lastActivity) || !_sessionHistories.TryRemove(sessionId, out var history))
        {
            _logger.LogWarning($"Attempted to remove non-existent session {sessionId}.");
            return;
        }

        _logger.LogInformation($"Removed session {sessionId}. Last active at {lastActivity}. History had {history.Count} messages.");
    }


    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
        var responseServiceObj = new LLMServiceObj { SessionId = serviceObj.SessionId };

        if (!_activeSessions.ContainsKey(serviceObj.SessionId))
        {
            throw new InvalidOperationException("Session does not exist.");
        }

        _logger.LogInformation("Sending input and waiting for response...");

        try
        {
            await _openAIRunnerSemaphore.WaitAsync(); // Wait to enter the semaphore

            string responseChoiceStr = "";
            // Retrieve or initialize the conversation history
            var history = _sessionHistories.GetOrAdd(serviceObj.SessionId, new List<ChatMessage>());

            var chatMessage = new ChatMessage();
            if (serviceObj.IsFunctionCallResponse)
            {
                chatMessage.Role = "function";
                chatMessage.Name = serviceObj.FunctionName;
                responseServiceObj.LlmMessage = "</functioncall-complete>";
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);

            }
            else chatMessage.Role = "user";
          
            chatMessage.Content = serviceObj.UserInput;
            history.Add(chatMessage);
            var completionResult = await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
            {
                Messages = history,
                Tools = _tools, // Your pre-defined tools
                ToolChoice = ToolChoice.Auto,
                MaxTokens = 200,
                Model = Models.Gpt_3_5_Turbo_0125
            });

            if (completionResult.Successful)
            {
                var choice = completionResult.Choices.First();
                responseChoiceStr = choice.Message.Content;
                _logger.LogInformation($"Received response: {responseChoiceStr}");

                // Process any function calls
                if (choice.Message.ToolCalls != null)
                {
                    responseServiceObj.UserInput = serviceObj.UserInput;
                    responseServiceObj.LlmMessage = "</functioncall>";
                    await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                    var fnCall = choice.Message.ToolCalls.FirstOrDefault();

                    var fn = fnCall.FunctionCall;
                    _logger.LogInformation($"Function call detected: {fn.Name}");

                    var json = JsonSerializer.Serialize(fn.ParseArguments());
                    var functionResponseServiceObj = new LLMServiceObj { SessionId = serviceObj.SessionId };

                    functionResponseServiceObj.IsFunctionCall = true;
                    functionResponseServiceObj.JsonFunction = json;
                    _logger.LogInformation($" Sending json: {json}");
                    functionResponseServiceObj.FunctionName = fn.Name;

                    await _responseProcessor.ProcessFunctionCall(functionResponseServiceObj);
                    responseChoiceStr = "";
                }

                responseServiceObj.LlmMessage = responseChoiceStr + "\n";
                // Send response back to client or system
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                responseServiceObj.LlmMessage = "<end-of-line>";
                responseServiceObj.TokensUsed = completionResult.Usage.TotalTokens;
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
              
            }
            else
            {
                _logger.LogError($"Completion failed: {completionResult.Error}");
                throw new Exception($"Error from OpenAI: {completionResult.Error}");
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
        }
    }

    private int CalculateTokens(string text)
    {
        // Basic token counting logic, could be improved with actual tokenization logic
        return text.Split(new char[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
    }

    // Implement other methods as needed...
}

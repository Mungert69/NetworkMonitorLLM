using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;

using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils;
using NetworkMonitor.LLM.Services;

namespace NetworkMonitor.LLM.Services;


public class ChatResponseBuilder
{
    private ITokenBroadcaster _tokenBroadcaster;
    private ILogger _logger;
    private bool _isXml;
    private LLMConfig _config;
    public ChatResponseBuilder(ILLMResponseProcessor responseProcessor, LLMConfig config, bool isXml, ILogger logger)
    {
        _logger = logger;
        _isXml = isXml;
        _config = config;
        _tokenBroadcaster = config!.CreateBroadcaster(responseProcessor, _logger, false);
        _tokenBroadcaster.Init(config);
    }

     private string CleanThinking(string response)
    {
        // Just return response if no thinking tokens are defined
        if (string.IsNullOrEmpty(_config.ThinkBeginToken) || string.IsNullOrEmpty(_config.ThinkEndToken))
        {
            return response;
        }
        // use ThinkBeginToken and ThinkEndToken from config to remove thinking parts
        string pattern = $"{Regex.Escape(_config.ThinkBeginToken)}(.*?){Regex.Escape(_config.ThinkEndToken)}";
        string cleanedResponse = Regex.Replace(response, pattern, "", RegexOptions.Singleline).Trim();
        return cleanedResponse;
    }

    // Add this method to the ChatResponseBuilder class
    public ChatCompletionCreateResponse BuildResponseFromOpenAI(ChatCompletionCreateResponse openAIResponse)
    {
        foreach (var choice in openAIResponse.Choices)
        {
            if (choice.Message == null) continue;
            var message = choice.Message;
            if (message == null || message.Content == null) continue;

            // Parse the content for XML function calls
            var functionCalls = _tokenBroadcaster.ParseInputForXml(message.Content);

            if (functionCalls.Any())
            {
                // Map parsed function calls to ToolCalls
                message.ToolCalls = functionCalls.Select(fc => new ToolCall
                {
                    Type = "function",
                    Id = StringUtils.NewToolCallId(),
                    FunctionCall = new FunctionCall
                    {
                        Name = fc.functionName,
                        Arguments = fc.json
                    }
                }).ToList();

                // For XML parsing, we might want to clear the content since we're using tool calls
                //message.Content = string.Empty; // Uncomment if needed
            }
        }

        return openAIResponse;
    }

    public ChatCompletionCreateResponse BuildResponse(HuggingFaceChatResponse responseObject)
    {
        var choices = responseObject.Choices;
        foreach (var choice in choices)
        {
            var message = choice.Message;
            if (message == null) continue;

            message.PopulateToolCallsFromRaw();

            bool hasStructuredToolCalls = message.ToolCalls != null && message.ToolCalls.Any();
            List<(string json, string functionName)> functionCalls = new();
            if (!hasStructuredToolCalls)
            {
                _logger.LogInformation($"Parsing function calls for message content: {message.Content}");

                if (string.IsNullOrEmpty(message.Content)) message.Content = message.ReasoningContent;
                if (_isXml) functionCalls = _tokenBroadcaster.ParseInputForXml(message.Content);
                else functionCalls = _tokenBroadcaster.ParseInputForJson(message.Content);

                if (functionCalls.Any())
                {
                    choice.FinishReason = "tool_calls";
                    foreach (var fc in functionCalls)
                    {
                        _logger.LogDebug($"Function call detected - Name: {fc.functionName}, JSON: {fc.json}");
                    }

                    choice.Message.ToolCalls = functionCalls.Select(fc => new ToolCall
                    {
                        Type = "function",
                        Id = StringUtils.NewToolCallId(),
                        FunctionCall = new FunctionCall
                        {
                            Name = fc.functionName,
                            Arguments = fc.json
                        }
                    }).ToList();

                    foreach (var toolCall in choice.Message.ToolCalls)
                    {
                        _logger.LogDebug($"ToolCall created - Type: {toolCall.Type}, Id: {toolCall.Id}, " + $"FunctionName: {toolCall.FunctionCall?.Name}, Arguments: {toolCall.FunctionCall?.Arguments}");
                    }
                }
                else
                {
                    choice.FinishReason = "stop";
                }
            }
            else
            {
                if (_isXml && !string.IsNullOrEmpty(message.Content))
                {
                    TryHydrateEmptyToolCallArgumentsFromXml(message);
                }
                if (string.IsNullOrEmpty(choice.FinishReason))
                {
                    choice.FinishReason = "tool_calls";
                }

                if (message.ToolCalls != null)
                    foreach (var toolCall in message.ToolCalls)
                    {
                        _logger.LogDebug($"ToolCall from response - Type: {toolCall.Type}, Id: {toolCall.Id}, " + $"FunctionName: {toolCall.FunctionCall?.Name}, Arguments: {toolCall.FunctionCall?.Arguments}");
                    }
            }
        }

        var chatResponse = new ChatCompletionCreateResponse
        {
            Choices = choices.Select(choice => new ChatChoiceResponse
            {
                Message = new ChatMessage
                {
                    Role = choice.Message.Role,
                    Content =  CleanThinking(choice.Message.Content),
                    ToolCalls = choice.Message.ToolCalls == null
                        ? null
                        : choice.Message.ToolCalls.Select(toolCall => new ToolCall
                        {
                            Type = toolCall.Type,
                            Id = toolCall.Id,
                            FunctionCall = new FunctionCall
                            {
                                Name = toolCall?.FunctionCall?.Name ?? "",
                                Arguments = toolCall?.FunctionCall?.Arguments ?? ""
                            }
                        }).ToList()
                },
                Index = choice.Index,
                FinishReason = choice.FinishReason
            }).ToList(),
            Usage = new UsageResponse
            {
                PromptTokens = responseObject.Usage.PromptTokens,
                CompletionTokens = responseObject.Usage.CompletionTokens,
                TotalTokens = responseObject.Usage.TotalTokens
            },
            Id = responseObject.Id,
            Model = responseObject.Model
        };
        //string payloadJson = JsonConvert.SerializeObject(chatResponse, Formatting.Indented);
        //_logger.LogInformation($"{payloadJson}");
        return chatResponse;
    }

    private void TryHydrateEmptyToolCallArgumentsFromXml(HuggingFaceMessage message)
    {
        if (message.ToolCalls == null || !message.ToolCalls.Any())
        {
            return;
        }

        var xmlCalls = _tokenBroadcaster.ParseInputForXml(message.Content);
        if (xmlCalls.Count == 0)
        {
            return;
        }

        var callsByName = new Dictionary<string, Queue<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (json, functionName) in xmlCalls)
        {
            if (!callsByName.TryGetValue(functionName, out var queue))
            {
                queue = new Queue<string>();
                callsByName[functionName] = queue;
            }
            queue.Enqueue(json);
        }

        var hydrated = false;
        foreach (var toolCall in message.ToolCalls)
        {
            var functionCall = toolCall.FunctionCall;
            if (functionCall == null)
            {
                continue;
            }

            var args = functionCall.Arguments ?? "";
            var isEmptyArgs = string.IsNullOrWhiteSpace(args) || args.Trim() == "{}";
            if (!isEmptyArgs)
            {
                continue;
            }

            var name = functionCall.Name ?? "";
            if (!callsByName.TryGetValue(name, out var queue) || queue.Count == 0)
            {
                continue;
            }

            functionCall.Arguments = queue.Dequeue();
            hydrated = true;
            _logger.LogDebug("Hydrated empty tool call arguments from XML for {FunctionName}.", name);
        }

        if (hydrated)
        {
            message.Content = string.Empty;
        }
    }
}

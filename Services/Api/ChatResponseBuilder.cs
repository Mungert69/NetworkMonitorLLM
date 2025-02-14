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
using Newtonsoft.Json;

namespace NetworkMonitor.LLM.Services;


public class ChatResponseBuilder
{
    private ITokenBroadcaster _tokenBroadcaster;
    private ILogger _logger;
    private bool _isXml;
    public ChatResponseBuilder(ILLMResponseProcessor responseProcessor,LLMConfig config, bool isXml, ILogger logger)
    {
        _logger = logger;
        _isXml = isXml;
        _tokenBroadcaster = config!.CreateBroadcaster(responseProcessor, _logger, false);
    }

    // Add this method to the ChatResponseBuilder class
    public ChatCompletionCreateResponse BuildResponseFromOpenAI(ChatCompletionCreateResponse openAIResponse)
    {
        foreach (var choice in openAIResponse.Choices)
        {
            if (choice.Message==null) continue;
            var message = choice.Message ;
            if (message == null) continue;

            // Parse the content for XML function calls
            var functionCalls = _tokenBroadcaster.ParseInputForXml(message.Content);

            if (functionCalls.Any())
            {
                // Map parsed function calls to ToolCalls
                message.ToolCalls = functionCalls.Select(fc => new ToolCall
                {
                    Type = "function",
                    Id = "call_" + StringUtils.GetNanoid(),
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
            // _logger.LogInformation($"Parsing function calls for message content: {choice.Message.Content}");

            // Parse the input using the broadcaster
            List<(string json, string functionName)> functionCalls;
            if (_isXml) functionCalls = _tokenBroadcaster.ParseInputForXml(choice.Message.Content);
            else functionCalls = _tokenBroadcaster.ParseInputForJson(choice.Message.Content);

            // Log the parsed results
            if (functionCalls.Any())
            {
                choice.FinishReason = "tool_calls";
                //_logger.LogInformation($"Parsed {functionCalls.Count} function calls.");
                foreach (var fc in functionCalls)
                {
                    //_logger.LogInformation($"Function call detected - Name: {fc.functionName}, JSON: {fc.json}");
                }

                // Map the parsed function calls to ToolCalls
                choice.Message.ToolCalls = functionCalls.Select(fc => new ToolCall
                {
                    Type = "function",
                    Id = "call_" + StringUtils.GetNanoid(),
                    FunctionCall = new FunctionCall
                    {
                        Name = fc.functionName,
                        Arguments = fc.json
                    }
                }).ToList();

                // Log the ToolCalls that were created
                foreach (var toolCall in choice.Message.ToolCalls)
                {
                    //_logger.LogInformation($"ToolCall created - Type: {toolCall.Type}, Id: {toolCall.Id}, " + $"FunctionName: {toolCall.FunctionCall.Name}, Arguments: {toolCall.FunctionCall.Arguments}");
                }
            }
            else
            {
                choice.FinishReason = "stop";
            }
        }

        var chatResponse = new ChatCompletionCreateResponse
        {
            Choices = choices.Select(choice => new ChatChoiceResponse
            {
                Message = new ChatMessage
                {
                    Role = choice.Message.Role,
                    Content = choice.Message.Content,
                    ToolCalls = choice.Message.ToolCalls.Select(toolCall => new ToolCall
                    {
                        Type = toolCall.Type,
                        Id = toolCall.Id,
                        FunctionCall = new FunctionCall
                        {
                            Name = toolCall?.FunctionCall?.Name ?? "",
                            Arguments = toolCall?.FunctionCall?.Arguments ?? ""
                        }
                    }).ToList() // Explicitly map each ToolCall and its FunctionCall
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
        string payloadJson = JsonConvert.SerializeObject(chatResponse, Formatting.Indented);
        _logger.LogInformation($"{payloadJson}");
        return chatResponse;
    }

}
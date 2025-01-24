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

public class OpenAIApi : ILLMApi
{
    private readonly OpenAIService _openAiService;
    private IToolsBuilder _toolsBuilder;
    private string _gptModel = "gpt-4o-mini";
    private ILogger _logger;


    public OpenAIApi(ILogger logger, OpenAIService openAiService, IToolsBuilder toolsBuilder, string gptModel)
    {
        _gptModel = gptModel;
        _logger=logger;
        _openAiService = openAiService;
        _toolsBuilder = toolsBuilder;
    }

    public string WrapFunctionResponse(string name, string funcStr)
    {
        // Return back funcStr unchanged
        return funcStr;

    }
    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        return _toolsBuilder.GetSystemPrompt(currentTime, serviceObj);

    }

    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens)
    {
        try
        {
            var chatResponse = await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
            {
                Messages = messages,
                MaxTokens = maxTokens,
                Model = _gptModel,
                Tools = _toolsBuilder.Tools,
                ToolChoice = _toolsBuilder.Tools != null ? ToolChoice.Auto : ToolChoice.None
            });
            return new ChatCompletionCreateResponseSuccess() { Success = chatResponse.Successful, Response = chatResponse };

        }
      catch (Exception ex)
{
    _logger.LogError($"Exception in CreateCompletionAsync: {ex.Message}");

    // Create a ChatCompletionCreateResponse with error details
    var errorChatResponse = new ChatCompletionCreateResponse
    {
        Id = Guid.NewGuid().ToString(),
        Model = _gptModel,
        Choices = new List<ChatChoiceResponse>(),
        Usage = new UsageResponse
        {
            PromptTokens = 0,
            CompletionTokens = 0,
            TotalTokens = 0
        },
        Error = new Error
        {
            MessageObject = ex.Message,
            Type = "Exception",
            Code = "500"
        }
    };

    return new ChatCompletionCreateResponseSuccess
    {
        Success = false,
        Response = errorChatResponse
    };
}

    }
}

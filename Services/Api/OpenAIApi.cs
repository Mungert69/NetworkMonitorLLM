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
using Newtonsoft.Json;

namespace NetworkMonitor.LLM.Services;

public class OpenAIApi : ILLMApi
{
    private readonly OpenAIService _openAiService;
    private IToolsBuilder _toolsBuilder;
    private string _gptModel = "gpt-5-mini";
    private ILogger _logger;
    private readonly bool _isXml;
    private readonly MLParams _mlParams;
    private readonly LLMConfig _config;
    private readonly string _modelVersion;
    private string _serviceID;
    private ILLMResponseProcessor _responseProcessor;
    private int _systemPromptCount;
    private readonly IList<ToolDefinition> _stableTools;

    public int SystemPromptCount { get => _systemPromptCount; }

    public LLMConfig Config => _config;

    public OpenAIApi(ILogger logger, MLParams mlParams, IToolsBuilder toolsBuilder, string serviceID, ILLMResponseProcessor responseProcessor, OpenAIService openAiService)
    {
        _mlParams = mlParams;
        _gptModel = mlParams.LlmGptModel;
        _serviceID = serviceID;
        _responseProcessor = responseProcessor;
        _logger = logger;
        _openAiService = openAiService;
        _toolsBuilder = toolsBuilder;
        _modelVersion = mlParams.LlmHFModelVersion;
        _isXml = _mlParams.XmlFunctionParsing;
        if (_gptModel.Contains("gpt") && !_gptModel.Contains("gpt-oss") )
        {
            _modelVersion = "gpt";
        }
        else if (_gptModel.Contains("gpt-oss") )
        {
            _modelVersion = "gpt_oss_min";
        }
        _config = LLMConfigFactory.GetConfig(_modelVersion);
        _stableTools = toolsBuilder.Tools.OrderBy(t => t.Function?.Name).ToList();


    }

    public string WrapFunctionResponse(string name, string funcStr)
    {
        // Return back funcStr unchanged
        return funcStr;

    }

    private string PromptFooter()
    {
        // For chatgpt we only alter the footer is we are using xml function calling
        if (_mlParams.XmlFunctionParsing) return Config.XmlPromptFooter;
        else return "";
    }
    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink = false)
    {
        string footer = PromptFooter();
        var systemMessages = _toolsBuilder.GetSystemPrompt(currentTime, serviceObj, "TurboLLM") ?? new List<ChatMessage>() { ChatMessage.FromSystem("") };
        _systemPromptCount = systemMessages.Count;
        systemMessages[0].Content = systemMessages[0].Content + footer;

        systemMessages.AddRange(NShotPromptFactory.GetPrompt(_serviceID, _mlParams.XmlFunctionParsing, currentTime, serviceObj, Config));
        _systemPromptCount = systemMessages.Count;
        return systemMessages;

    }

    public string GetFunctionNamesAsString(string separator = ", ")
    {
        return _toolsBuilder.GetFunctionNamesAsString();
    }
    public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        var resumeSystemMessages = _toolsBuilder.GetResumeSystemPrompt(currentTime, serviceObj, "TurboLLM");

        return resumeSystemMessages;

    }

    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxCompletionTokens, LLMServiceObj serviceObj)
    {
        try
        {
            //_logger.LogInformation(JsonConvert.SerializeObject(_toolsBuilder.Tools, Formatting.Indented));
           // _logger.LogInformation($"TOOLS_SHA256={HashHelper.ComputeSha256Hash(JsonConvert.SerializeObject(_stableTools))}");

            //  string payloadJson = JsonConvert.SerializeObject(messages, Formatting.Indented);
            //_logger.LogInformation($"{payloadJson}");
            var chatCompletionCreateRequest = new ChatCompletionCreateRequest
            {
                Messages = messages,
                MaxCompletionTokens = maxCompletionTokens,
                Model = _gptModel,
                Tools = _stableTools
            };
            var chatResponse = await _openAiService.ChatCompletion.CreateCompletion(chatCompletionCreateRequest);
            if (_isXml)
            {
                var chatResponseBuilder = new ChatResponseBuilder(_responseProcessor, Config, _isXml, _logger);
                chatResponse = chatResponseBuilder.BuildResponseFromOpenAI(chatResponse);
            }
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

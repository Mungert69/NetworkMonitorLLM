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


public class HuggingFaceApi : ILLMApi
{
    private readonly ILogger _logger;
    private readonly HttpClient _httpClient;
    private readonly string _apiUrl;
    private readonly string _authToken;
    private readonly string _modelVersion;
    private readonly string _modelID;
    private readonly string _serviceID;
    private readonly bool _isXml;
    private readonly MLParams _mlParams;
    private readonly LLMConfig _config;

    private IToolsBuilder _toolsBuilder;

    public HuggingFaceApi(ILogger logger, MLParams mlParams, IToolsBuilder toolsBuilder, string serviceID)
    {
        _logger = logger;
        _toolsBuilder = toolsBuilder;
        _serviceID=serviceID;
        _httpClient = new HttpClient();
        _httpClient.Timeout = TimeSpan.FromMilliseconds(120000); 
        _mlParams = mlParams;
        _modelVersion = mlParams.LlmHFModelVersion;
        _modelID = mlParams.LlmHFModelID;
        _authToken = mlParams.LlmHFKey;
        _isXml=_mlParams.XmlFunctionParsing;
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _authToken);
        _apiUrl=mlParams.LlmHFUrl.TrimEnd();
        if (!_apiUrl.Contains("completions"))
        _apiUrl = $"{mlParams.LlmHFUrl.TrimEnd('/')}/models/{_modelID}/v1/chat/completions";
        
        _config = LLMConfigFactory.GetConfig(_modelVersion);
        _logger.LogInformation($"Initialized Hugging Face API with URL: {_apiUrl}");
    }

    public string WrapFunctionResponse(string name, string funcStr)
    {
        return string.Format(_config.FunctionResponse, name, funcStr);

    }
    private string ToolsWrapper(string toolsStr)
    {
        return string.Format(_config.FunctionDefsWrap, toolsStr);
    }



    private string PromptFooter()
    {
        if (_mlParams.XmlFunctionParsing) return _config.XmlPromptFooter;
        else return _config.PromptFooter;
    }

    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {

        string toolsJson = ToolsWrapper(JsonToolsBuilder.BuildToolsJson(_toolsBuilder.Tools));
        // List<ChatMessage> systemPrompt=_toolsBuilder.GetSystemPrompt(currentTime, serviceObj);
        string footer = PromptFooter();
        var systemMessages = _toolsBuilder.GetSystemPrompt(currentTime, serviceObj,"HugLLM");
        systemMessages[0].Content = toolsJson + systemMessages[0].Content + footer;
        _logger.LogInformation($" Using SYSTEM prompt\n\n{systemMessages[0].Content}");
        systemMessages.AddRange(NShotPromptFactory.GetPrompt(_serviceID,_isXml, currentTime, serviceObj));
        return systemMessages;
    }

    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens)
    {
        var toolsJson = JsonToolsBuilder.BuildToolsJson(_toolsBuilder.Tools);
        var tools = JsonConvert.DeserializeObject<List<object>>(toolsJson);
        try
        {
            var payload = new
            {
                model = _modelID,
                messages = messages.Select(m => new
                {
                    role = m.Role,
                    content = m.Content
                }).ToList(),
                max_tokens = maxTokens,
                stream = false,
                temperture = 0.1
            };
            string payloadJson = JsonConvert.SerializeObject(payload, Formatting.Indented);

            string responseContent = await SendHttpRequestAsync(payloadJson);
            // Deserialize using Newtonsoft.Json
            var responseObject = JsonConvert.DeserializeObject<HuggingFaceChatResponse>(responseContent);


           var chatResponseBuilder=new ChatResponseBuilder(_config,_isXml, _logger);
           var chatResponse=chatResponseBuilder.BuildResponse(responseObject);
          
            return new ChatCompletionCreateResponseSuccess { Success = true, Response = chatResponse };
        }
        catch (Exception ex)
        {
            _logger.LogError($"Exception in CreateCompletionAsync: {ex.Message}");

            // Create a ChatCompletionCreateResponse with error details
            var errorChatResponse = new ChatCompletionCreateResponse
            {
                Id = Guid.NewGuid().ToString(),
                Model = _modelID,
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
    private async Task<string> SendHttpRequestAsync(string payloadJson)
    {
        const int maxRetries = 3;
        const int delayBetweenRetries = 10000; 
        const int timeout = 120000;

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                var content = new StringContent(payloadJson, Encoding.UTF8, "application/json");
                _logger.LogInformation($"Attempt {attempt}: Sending request to Hugging Face API...");

                using (var cts = new CancellationTokenSource(timeout))
                {
                    var response = await _httpClient.PostAsync(_apiUrl, content, cts.Token);

                    if (!response.IsSuccessStatusCode)
                    {
                        string errorContent = await response.Content.ReadAsStringAsync();
                        _logger.LogError($"Attempt {attempt}: Error {response.StatusCode}, Content: {errorContent}");

                        if (attempt < maxRetries)
                        {
                            _logger.LogInformation($"Retrying in {delayBetweenRetries / 1000} seconds...");
                            await Task.Delay(delayBetweenRetries);
                            continue;
                        }

                        return null; // Return null if all retries fail
                    }

                    string responseContent = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Attempt {attempt}: Successfully received response from Hugging Face API.");
                    return responseContent;
                }
            }
            catch (TaskCanceledException ex) when (!ex.CancellationToken.IsCancellationRequested)
            {
                _logger.LogError($"Attempt {attempt}: Request timed out after {timeout / 1000} seconds.");

                if (attempt < maxRetries)
                {
                    _logger.LogInformation($"Retrying in {delayBetweenRetries / 1000} seconds...");
                    await Task.Delay(delayBetweenRetries);
                    continue;
                }

                throw new TimeoutException("All retry attempts timed out.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Attempt {attempt}: Exception occurred: {ex.Message}");
                if (attempt < maxRetries)
                {
                    _logger.LogInformation($"Retrying in {delayBetweenRetries / 1000} seconds...");
                    await Task.Delay(delayBetweenRetries);
                    continue;
                }
                throw;
            }
        }

        // If all retries are exhausted, return null
        _logger.LogError("Should not get here.");
        return null;
    }

}



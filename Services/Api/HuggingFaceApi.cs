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
    private readonly string _model;
    private readonly string _modelID;
    private readonly LLMConfig _config;

    private IToolsBuilder _toolsBuilder;

    public HuggingFaceApi(ILogger logger, IToolsBuilder toolsBuilder, string apiUrl, string authToken, string modelID, string model)
    {
        _logger = logger;
        _toolsBuilder = toolsBuilder;
        _httpClient = new HttpClient();
        _model = model;
        _modelID = modelID;
        _authToken = authToken;
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authToken);
        _apiUrl = $"{apiUrl.TrimEnd('/')}/models/{modelID}/v1/chat/completions";
        _config = LLMConfigFactory.GetConfig(model);
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
        return _config.PromptFooter;
    }

    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
      
        string toolsJson = ToolsWrapper(JsonToolsBuilder.BuildToolsJson(_toolsBuilder.Tools));
        // List<ChatMessage> systemPrompt=_toolsBuilder.GetSystemPrompt(currentTime, serviceObj);
        string footer = PromptFooter();
        var systemMessages = _toolsBuilder.GetSystemPrompt(currentTime, serviceObj);
        systemMessages[0].Content = toolsJson + systemMessages[0].Content + footer;

        return systemMessages;
    }

    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens)
    {
        var tokenBroadcaster = _config.CreateBroadcaster(null, _logger, false);
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


            // Use the broadcaster to parse function calls
            foreach (var choice in responseObject.Choices)
            {
                // _logger.LogInformation($"Parsing function calls for message content: {choice.Message.Content}");

                // Parse the input using the broadcaster
                var functionCalls = tokenBroadcaster.ParseInputForJson(choice.Message.Content);

                // Log the parsed results
                if (functionCalls.Any())
                {
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
                    _logger.LogWarning($"No function calls were parsed for the message content: {choice.Message.Content}");
                }
            }

            var chatResponse = new ChatCompletionCreateResponse
            {
                Choices = responseObject.Choices.Select(choice => new ChatChoiceResponse
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
                                Name = toolCall.FunctionCall.Name,
                                Arguments = toolCall.FunctionCall.Arguments
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
        const int delayBetweenRetries = 20000; // 5 seconds in milliseconds
        const int timeout = 60000; // 20 seconds in milliseconds

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
                throw; 
            }
        }

        // If all retries are exhausted, return null
        _logger.LogError("Should not get here.");
        return null;
    }

}

public class HuggingFaceChatResponse
{
    [JsonProperty("object")]
    public string Object { get; set; } = string.Empty; // Maps to "object"

    [JsonProperty("id")]
    public string Id { get; set; } = string.Empty; // Maps to "id"

    [JsonProperty("created")]
    public long Created { get; set; } = 0; // Maps to "created"

    [JsonProperty("model")]
    public string Model { get; set; } = string.Empty; // Maps to "model"

    [JsonProperty("system_fingerprint")]
    public string SystemFingerprint { get; set; } = string.Empty; // Maps to "system_fingerprint"

    [JsonProperty("choices")]
    public List<HuggingFaceChoice> Choices { get; set; } = new List<HuggingFaceChoice>(); // Maps to "choices"

    [JsonProperty("usage")]
    public HuggingFaceUsage Usage { get; set; } = new HuggingFaceUsage(); // Maps to "usage"
}

public class HuggingFaceChoice
{
    [JsonProperty("index")]
    public int Index { get; set; } = 0; // Maps to "index"

    [JsonProperty("message")]
    public HuggingFaceMessage Message { get; set; } = new HuggingFaceMessage(); // Maps to "message"

    [JsonProperty("logprobs")]
    public object Logprobs { get; set; } = null; // Maps to "logprobs"

    [JsonProperty("finish_reason")]
    public string FinishReason { get; set; } = string.Empty; // Maps to "finish_reason"
}

public class HuggingFaceMessage
{
    [JsonProperty("role")]
    public string Role { get; set; } = string.Empty; // Maps to "role"

    [JsonProperty("content")]
    public string Content { get; set; } = string.Empty; // Maps to "content"

    [JsonIgnore] // Not serialized/deserialized unless you add it explicitly in JSON
    public List<ToolCall> ToolCalls { get; set; } = new List<ToolCall>();
}

public class HuggingFaceUsage
{
    [JsonProperty("prompt_tokens")]
    public int PromptTokens { get; set; } = 0; // Maps to "prompt_tokens"

    [JsonProperty("completion_tokens")]
    public int CompletionTokens { get; set; } = 0; // Maps to "completion_tokens"

    [JsonProperty("total_tokens")]
    public int TotalTokens { get; set; } = 0; // Maps to "total_tokens"
}


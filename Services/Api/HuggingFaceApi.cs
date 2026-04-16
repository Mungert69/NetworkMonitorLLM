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
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

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
    private readonly float _temperature;
    private readonly MLParams _mlParams;
    private readonly LLMConfig _config;
    private readonly bool _supportsStructuredTools;

    public LLMConfig Config => _config;
    private bool _isStream;

    private IToolsBuilder _toolsBuilder;
    private ILLMResponseProcessor _responseProcessor;
    private int _systemPromptCount;

    public int SystemPromptCount { get => _systemPromptCount; }

    public HuggingFaceApi(ILogger logger, MLParams mlParams, IToolsBuilder toolsBuilder, string serviceID, ILLMResponseProcessor responseProcessor, bool isStream = false)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _toolsBuilder = toolsBuilder;
        _serviceID = serviceID;
        _isStream = isStream;
        _httpClient = new HttpClient();
        // Use per-request CancellationToken timeout in SendHttpRequestAsync.
        // A fixed HttpClient.Timeout here would override configured HfRequestTimeoutSeconds.
        _httpClient.Timeout = Timeout.InfiniteTimeSpan;
        _mlParams = mlParams;
        if (!float.TryParse(_mlParams.LlmTemp, out float temperature))
        {
            _logger.LogWarning($"Invalid temperature value '{_mlParams.LlmTemp}', using default 0.1");
            temperature = 0.3f; // Default value
        }
        _temperature = temperature;
        _modelVersion = mlParams.LlmHFModelVersion;
        _modelID = mlParams.LlmHFModelID;
        _authToken = mlParams.LlmHFKey;     
        _isXml = _mlParams.XmlFunctionParsing;
        //_httpClient.DefaultRequestHeaders.Add("api-key", _authToken);
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _authToken);
        _apiUrl = mlParams.LlmHFUrl.TrimEnd();
        if (_apiUrl.Contains("api-inference"))
            _apiUrl = $"{mlParams.LlmHFUrl.TrimEnd('/')}/models/{_modelID}/v1/chat/completions";

        _config = LLMConfigFactory.GetConfig(_modelVersion);
        _supportsStructuredTools = mlParams.LlmHfSupportsFunctionCalling;
        _logger.LogInformation($"Initialized Hugging Face API with URL: {_apiUrl} using model id {_modelID}");
    }

    public string WrapFunctionResponse(string name, string funcStr)
    {
        if (_mlParams.LlmUseToolRoleForFunctionResponses) return funcStr;
        return string.Format(_config.FunctionResponse, name, funcStr);

    }
    private string ToolsWrapper(string toolsStr)
    {
        return string.Format(_config.FunctionDefsWrap, toolsStr);
    }

   

    private string PromptFooter()
    {
        if (_supportsStructuredTools && !_mlParams.XmlFunctionParsing)
        {
            return "";
        }
        return _mlParams.XmlFunctionParsing ? _config.XmlPromptFooter : _config.PromptFooter;
    }

    public string GetFunctionNamesAsString(string separator = ", ")
    {
        return _toolsBuilder.GetFunctionNamesAsString();
    }

    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink)
    {
        string toolsJson = "";
        if (!_supportsStructuredTools) toolsJson = ToolsWrapper(JsonToolsBuilder.BuildToolsJson(_toolsBuilder.Tools));
        // List<ChatMessage> systemPrompt=_toolsBuilder.GetSystemPrompt(currentTime, serviceObj);
        string footer = PromptFooter();
        var systemMessages = _toolsBuilder.GetSystemPrompt(currentTime, serviceObj, "HugLLM") ?? new List<ChatMessage>() { ChatMessage.FromSystem("") };
        string noThinkToken = "";
        if (noThink) noThinkToken = " " + _config.NoThinkToken + " ";
        systemMessages[0].Content = toolsJson + systemMessages[0].Content + footer + noThinkToken;
        //_logger.LogInformation($" Using SYSTEM prompt\n\n{systemMessages[0].Content}");
        if (!_mlParams.NoNShot) systemMessages.AddRange(NShotPromptFactory.GetPrompt(_serviceID, _isXml, currentTime, serviceObj, _config));
     
        _systemPromptCount = systemMessages.Count;
        return systemMessages;
    }

    public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        var resumeSystemMessages = _toolsBuilder.GetResumeSystemPrompt(currentTime, serviceObj, "HugLLM");

        return resumeSystemMessages;

    }
    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens, LLMServiceObj serviceObj)
    {
        string? responseContent = null;
        var toolsPayload = _supportsStructuredTools
            ? JsonToolsBuilder.BuildOpenAIToolsPayload(_toolsBuilder.Tools)
            : null;

        var structuredMessages = _supportsStructuredTools
            ? ConvertMessagesForOpenAIToolMode(messages)
            : null;
        var (multimodalCount, imagePartCount) = GetContentShapeStats(messages);
        _logger.LogInformation(
            "HugLLM request content mode: StructuredTools={StructuredTools}, MultimodalMessages={MultimodalMessages}, ImageParts={ImageParts}, TotalMessages={TotalMessages}",
            _supportsStructuredTools,
            multimodalCount,
            imagePartCount,
            messages.Count);

        try
        {
            object payload = BuildPayload(messages, maxTokens, toolsPayload, structuredMessages);

            HuggingFaceChatResponse? responseObject = null;
            string payloadJson = JsonConvert.SerializeObject(payload, Formatting.Indented, new JsonSerializerSettings
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver(),
                NullValueHandling = NullValueHandling.Ignore
            });

            _logger.LogDebug($"PAYLOAD =====> {payloadJson}");

            if (!_isStream)
            {
                responseContent = await SendHttpRequestAsync(payloadJson);
                if (responseContent != null)
                {
                    LogRawProviderToolCalls(responseContent);
                    responseObject = JsonConvert.DeserializeObject<HuggingFaceChatResponse>(responseContent);
                }

            }
            else
            {
                var process = new HuggingFaceProcessWrapper(_httpClient);
                await process.InitializeRequest(_apiUrl, payloadJson);
                var tokenBroadcaster = _config.CreateBroadcaster(_responseProcessor, _logger, false);
                tokenBroadcaster.Init(_config);
                tokenBroadcaster.UseHttpProcess = true;
                tokenBroadcaster.IsAddAssistant = true;
                await tokenBroadcaster.SetUp(serviceObj, true, 1);

                await tokenBroadcaster.BroadcastAsync(process, serviceObj, "");
                responseObject = new HuggingFaceChatResponse
                {
                    Id = Guid.NewGuid().ToString(),
                    Choices = new List<HuggingFaceChoice>
                    {
                        new HuggingFaceChoice
                            {
                                Message = new HuggingFaceMessage { Role = "assistant", Content = tokenBroadcaster.ResponseContent },
                                FinishReason = "stop"
                            }
                    },
                    Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    Usage = new HuggingFaceUsage()
                };


            }
            if (responseObject == null)
            {
                throw new Exception(" Reponse is null");
            }
            var chatResponseBuilder = new ChatResponseBuilder(_responseProcessor, _config, _isXml, _logger);
            var chatResponse = chatResponseBuilder.BuildResponse(responseObject);

            return new ChatCompletionCreateResponseSuccess { Success = true, Response = chatResponse };
        }
        catch (Exception ex)
        {
            _logger.LogError($"Exception in CreateCompletionAsync: {ex.Message}");
            if (!string.IsNullOrWhiteSpace(responseContent))
            {
                var snippet = responseContent.Length > 2000
                    ? responseContent.Substring(0, 2000) + "...(truncated)"
                    : responseContent;
                _logger.LogError("Raw provider response (truncated): {ResponseSnippet}", snippet);
            }

            // Create a ChatCompletionCreateResponse with error details
            var errorChatResponse = GetErrorResponse(ex.Message);
            return new ChatCompletionCreateResponseSuccess
            {
                Success = false,
                Response = errorChatResponse
            };
        }


    }

    private void LogRawProviderToolCalls(string responseContent)
    {
        try
        {
            var root = JToken.Parse(responseContent);
            var toolCalls = root.SelectToken("choices[0].message.tool_calls");
            if (toolCalls == null || toolCalls.Type == JTokenType.Null)
            {
                return;
            }

            var argsToken = root.SelectToken("choices[0].message.tool_calls[0].function.arguments");
            var argsType = argsToken?.Type.ToString() ?? "null";
            _logger.LogInformation("HugLLM raw tool_calls detected. First function.arguments token type: {ArgumentsTokenType}", argsType);
            _logger.LogDebug("HugLLM raw tool_calls payload: {ToolCallsJson}", toolCalls.ToString(Formatting.None));
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Failed to inspect raw provider tool_calls payload: {Message}", ex.Message);
        }
    }

    private object BuildPayload(List<ChatMessage> messages, int maxTokens, object? toolsPayload, List<Dictionary<string, object?>>? structuredMessages)
    {
        if (_supportsStructuredTools && structuredMessages != null)
        {
            var payloadDict = new Dictionary<string, object?>
            {
                ["model"] = _modelID,
                ["messages"] = structuredMessages,
                ["max_tokens"] = maxTokens,
                ["stream"] = _isStream,
                ["temperature"] = _temperature,
                ["response_format"] = new { type = "text" }
            };

            if (toolsPayload is System.Collections.IEnumerable enumerable && enumerable.Cast<object?>().Any())
            {
                payloadDict["tools"] = toolsPayload;
                payloadDict["tool_choice"] = "auto";
            }
            else
            {
                payloadDict["tool_choice"] = "none";
            }

            return payloadDict;
        }

        return new
        {
            model = _modelID,
            messages = messages.Select(m => new
            {
                role = (!_mlParams.LlmUseToolRoleForFunctionResponses && string.Equals(m.Role?.ToString(), "tool", StringComparison.OrdinalIgnoreCase))
                    ? "user"
                    : m.Role?.ToString(),
                content = FlattenContentForTextOnly(m)
            }).ToList(),
            max_tokens = maxTokens,
            stream = _isStream,
            temperature = _temperature,
            response_format = new { type = "text" }
        };
    }

    private static string FlattenContentForTextOnly(ChatMessage message)
    {
        if (!string.IsNullOrWhiteSpace(message.Content) &&
            !message.Content.Contains("System.Collections.Generic.List`1[", StringComparison.Ordinal))
        {
            return message.Content;
        }

        var messageContents = ExtractMessageContents(message);
        if (messageContents.Count == 0)
        {
            return string.Empty;
        }

        var parts = new List<string>();
        foreach (var part in messageContents)
        {
            if (string.Equals(part.Type, "text", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(part.Text))
            {
                parts.Add(part.Text);
            }
            else if (string.Equals(part.Type, "image_url", StringComparison.OrdinalIgnoreCase) &&
                     !string.IsNullOrWhiteSpace(part.ImageUrl?.Url))
            {
                parts.Add($"[image_url: {part.ImageUrl.Url}]");
            }
        }

        return string.Join("\n", parts);
    }

    private List<Dictionary<string, object?>> ConvertMessagesForOpenAIToolMode(IEnumerable<ChatMessage> messages)
    {
        var formatted = new List<Dictionary<string, object?>>();

        foreach (var message in messages)
        {
            var entry = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["role"] = OpenAIWireFormat.Role(message)
            };

            if (!string.IsNullOrEmpty(message.Name) && OpenAIWireFormat.IsRole(message, "tool"))
            {
                entry["name"] = message.Name;
            }

            if (!string.IsNullOrEmpty(message.ToolCallId))
            {
                entry["tool_call_id"] = message.ToolCallId;
            }

            var toolCalls = message.ToolCalls ?? new List<ToolCall>();
            if (toolCalls.Any())
            {
                entry["content"] = OpenAIWireFormat.BuildStructuredContent(message);
                entry["tool_calls"] = toolCalls.Select(tc =>
                    new Dictionary<string, object?>
                    {
                        ["id"] = tc.Id,
                        ["type"] = OpenAIWireFormat.ToolCallType(tc),
                        ["function"] = tc.FunctionCall == null
                            ? null
                            : new Dictionary<string, object?>
                            {
                                ["name"] = tc.FunctionCall.Name,
                                ["arguments"] = tc.FunctionCall.Arguments
                            }
                    }).ToList();
            }
            else
            {
                entry["content"] = OpenAIWireFormat.BuildStructuredContent(message);
            }

            formatted.Add(entry);
        }

        return formatted;
    }

    private static List<MessageContent> ExtractMessageContents(ChatMessage message)
    {
        return OpenAIWireFormat.ExtractMessageContents(message);
    }

    private static (int multimodalCount, int imagePartCount) GetContentShapeStats(IEnumerable<ChatMessage> messages)
    {
        int multimodalCount = 0;
        int imagePartCount = 0;

        foreach (var message in messages)
        {
            var parts = ExtractMessageContents(message);
            if (parts.Count == 0) continue;
            multimodalCount++;
            imagePartCount += parts.Count(p => string.Equals(p.Type, "image_url", StringComparison.OrdinalIgnoreCase));
        }

        return (multimodalCount, imagePartCount);
    }

    private ChatCompletionCreateResponse GetErrorResponse(string message) =>
          new ChatCompletionCreateResponse
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
                  MessageObject = message,
                  Type = "Exception",
                  Code = "500"
              }
          };


    private async Task<string?> SendHttpRequestAsync(string payloadJson)
    {
        int maxRetries = _mlParams.HfRetryMaxAttempts;
        int delayBetweenRetries = _mlParams.HfRetryDelaySeconds * 1000; // Convert to milliseconds
        int timeout = _mlParams.HfRequestTimeoutSeconds * 1000; // Convert to milliseconds

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
                    _logger.LogDebug($"Attempt {attempt}: Successfully received response from Hugging Face API. {responseContent}");
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

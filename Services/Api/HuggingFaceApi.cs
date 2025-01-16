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

public class ChatCompletionCreateResponseSuccess
{
    public bool Success { get; set; }
    public ChatCompletionCreateResponse Response { get; set; }
}

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

    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        string header = "\nHere is a list of functions in JSON format that you can invoke:\n";

        string toolsJson = JsonToolsBuilder.BuildToolsJson(_toolsBuilder.Tools);
        // List<ChatMessage> systemPrompt=_toolsBuilder.GetSystemPrompt(currentTime, serviceObj);
       string footer = "Think very carefully before calling functions.\n\n" +
 "If you choose to call a function, ONLY reply in the following format:\n\n" +
 "{\"name\": \"{function_name}\", \"parameters\": {parameters}}\n\n" +
 "Where:\n\n" +
 "    function_name: The name of the function being called.\n" +
 "    parameters: A JSON object where the argument names (keys) are taken from the function definition, and the argument values (values) must be in the correct data types (such as strings, numbers, booleans, etc.) as specified in the function's definition.\n\n" +
 "Notes:\n\n" +
 "    Numbers remain numbers (e.g., 123, 59.5).\n" +
 "    Booleans are true or false, not \"true\" or \"false\".\n" +
 "    Strings are enclosed in quotes (e.g., \"example\").\n" +
 "    Refer to the function definitions to ensure all parameters of the correct types.\n\n" +
 "Important: You will call functions only when necessary. Checking with the user before calling more functions.\n" +
 "Important! All json in your responses will be interpreted as a function call. You will only provide json in your responses when you intend to call a function.";

    var systemMessages=_toolsBuilder.GetSystemPrompt(currentTime, serviceObj);
    systemMessages[0].Content=header + toolsJson + systemMessages[0].Content+ footer;
 
    return systemMessages;
    }

    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens)
    {
        var tokenBroadcaster = _config.CreateBroadcaster(null, _logger, false);
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
                stream = false
            };
            string payloadJson = JsonConvert.SerializeObject(payload, Formatting.Indented);

            //_logger.LogInformation($"Payload JSON: {payloadJson}");
            var content = new StringContent(payloadJson, Encoding.UTF8, "application/json");

            string contentString = await content.ReadAsStringAsync();
            //_logger.LogInformation($"StringContent content: {contentString}");

            var response = await _httpClient.PostAsync(_apiUrl, content);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError($"Error: {response.StatusCode}, Content: {await response.Content.ReadAsStringAsync()}");
                return new ChatCompletionCreateResponseSuccess { Success = false };
            }

            var responseContent = await response.Content.ReadAsStringAsync();
            //_logger.LogInformation($"Received response: {responseContent}");

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
            return new ChatCompletionCreateResponseSuccess { Success = false };
        }
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


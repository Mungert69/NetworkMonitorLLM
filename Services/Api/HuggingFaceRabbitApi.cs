using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;

using System;
using System.IO;
using System.Text;
using System.Text.Json;
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
using Newtonsoft.Json.Serialization;


namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    /// HuggingFace model served behind RabbitMQ (OpenAI-compatible Space).
    /// Matches ILLMApi interface.
    /// </summary>
    public sealed class HuggingFaceRabbitApi : ILLMApi, IDisposable
    {
        private readonly RabbitTransport _mq;
        private readonly IToolsBuilder _toolsBuilder;
        private readonly ILogger _logger;
        private readonly ILLMResponseProcessor _responseProcessor;
        private readonly MLParams _mlParams;
        private readonly LLMConfig _config;

        private readonly string _serviceID;
        private readonly string _modelID;
        private readonly string _modelVersion;
        private readonly bool _isXml;
        private int _systemPromptCount;

        public int SystemPromptCount => _systemPromptCount;
        public LLMConfig Config => _config;

        public HuggingFaceRabbitApi(
            ILogger logger,
            MLParams mlParams,
            IToolsBuilder toolsBuilder,
            string serviceID,
            ILLMResponseProcessor responseProcessor,
            RabbitTransport rabbitTransport
        )
        {
            _logger = logger;
            _mlParams = mlParams;
            _toolsBuilder = toolsBuilder;
            _serviceID = serviceID;
            _responseProcessor = responseProcessor;
            _mq = rabbitTransport ?? throw new ArgumentNullException(nameof(rabbitTransport));

            _modelID = mlParams.LlmSpaceModelID;
            _modelVersion = mlParams.LlmHFModelVersion;
            _isXml = mlParams.XmlFunctionParsing;

            _config = LLMConfigFactory.GetConfig(_modelVersion);
        }

        public void Dispose()
        {
            try { _mq?.Dispose(); } catch { }
        }

        public string WrapFunctionResponse(string name, string funcStr)
            => string.Format(_config.FunctionResponse, name, funcStr);

        private string ToolsWrapper(string toolsStr)
            => string.Format(_config.FunctionDefsWrap, toolsStr);

        private string PromptFooter()
            => _mlParams.XmlFunctionParsing ? _config.XmlPromptFooter : _config.PromptFooter;

        public string GetFunctionNamesAsString(string separator = ", ")
            => _toolsBuilder.GetFunctionNamesAsString();

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink = false)
        {
            string toolsJson = ToolsWrapper(JsonToolsBuilder.BuildToolsJson(_toolsBuilder.Tools));
            var systemMessages = _toolsBuilder.GetSystemPrompt(currentTime, serviceObj, "HugRabbit")
                                 ?? new List<ChatMessage>() { ChatMessage.FromSystem("") };

            string footer = PromptFooter();
            string noThinkToken = noThink ? " " + _config.NoThinkToken + " " : "";

            systemMessages[0].Content = toolsJson + (systemMessages[0].Content ?? "") + footer + noThinkToken;

            systemMessages.AddRange(NShotPromptFactory.GetPrompt(_serviceID, _isXml, currentTime, serviceObj, _config));
            _systemPromptCount = systemMessages.Count;
            return systemMessages;
        }

        public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj)
            => _toolsBuilder.GetResumeSystemPrompt(currentTime, serviceObj, "HugRabbit");

        public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(
            List<ChatMessage> messages,
            int maxTokens,
            LLMServiceObj serviceObj)
        {
            try
            {
                var req = BuildOpenAIChatRequest(messages, maxTokens, serviceObj, _toolsBuilder, _modelID, _mlParams);

                var content = new System.Text.StringBuilder();
                string? finishReason = null;
                string role = "assistant";
                string id = Guid.NewGuid().ToString("N");
                string model = _modelID;

                await foreach (var chunkJson in _mq.CreateChatCompletionStreamAsync(req))
                {
                    using var je = JsonDocument.Parse(chunkJson);

                    if (je.RootElement.TryGetProperty("object", out var objEl) &&
                        objEl.GetString() == "chat.completion")
                    {
                        var finalFromServer = JsonConvert.DeserializeObject<ChatCompletionCreateResponse>(chunkJson);
                        if (finalFromServer != null)
                        {
                            var responseToReturn = _isXml
                                ? new ChatResponseBuilder(_responseProcessor, _config, _isXml, _logger)
                                      .BuildResponseFromOpenAI(finalFromServer)
                                : finalFromServer;

                            return new ChatCompletionCreateResponseSuccess
                            {
                                Success = true,
                                Response = responseToReturn
                            };
                        }
                    }

                    if (je.RootElement.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String)
                        id = idEl.GetString() ?? id;
                    if (je.RootElement.TryGetProperty("model", out var modelEl) && modelEl.ValueKind == JsonValueKind.String)
                        model = modelEl.GetString() ?? model;

                    if (je.RootElement.TryGetProperty("choices", out var choices) &&
                        choices.ValueKind == JsonValueKind.Array &&
                        choices.GetArrayLength() > 0)
                    {
                        var c0 = choices[0];

                        if (c0.TryGetProperty("delta", out var delta) && delta.ValueKind == JsonValueKind.Object)
                        {
                            if (delta.TryGetProperty("role", out var roleEl) && roleEl.ValueKind == JsonValueKind.String)
                                role = roleEl.GetString() ?? role;

                            if (delta.TryGetProperty("content", out var textEl) && textEl.ValueKind == JsonValueKind.String)
                                content.Append(textEl.GetString());
                        }

                        if (c0.TryGetProperty("finish_reason", out var fr) && fr.ValueKind == JsonValueKind.String)
                            finishReason = fr.GetString();
                    }
                }

                var synthesized = new ChatCompletionCreateResponse
                {
                    Id = id,
                    Model = model,
                    Choices = new List<ChatChoiceResponse>
                    {
                        new()
                        {
                            Index = 0,
                            FinishReason = finishReason ?? "stop",
                            Message = new()
                            {
                                Role = role,
                                Content = content.ToString()
                            }
                        }
                    },
                    Usage = new UsageResponse { PromptTokens = 0, CompletionTokens = 0, TotalTokens = 0 }
                };

                var finalResponse = _isXml
                    ? new ChatResponseBuilder(_responseProcessor, _config, _isXml, _logger)
                        .BuildResponseFromOpenAI(synthesized)
                    : synthesized;

                return new ChatCompletionCreateResponseSuccess
                {
                    Success = true,
                    Response = finalResponse
                };
            }
            catch (Exception ex)
            {
                _logger.LogError($"Exception in CreateCompletionAsync (HugRabbit): {ex.Message}");

                var errorChatResponse = new ChatCompletionCreateResponse
                {
                    Id = Guid.NewGuid().ToString(),
                    Model = _modelID,
                    Choices = new List<ChatChoiceResponse>(),
                    Usage = new UsageResponse(),
                    Error = new Error { MessageObject = ex.Message, Type = "Exception", Code = "500" }
                };

                return new ChatCompletionCreateResponseSuccess
                {
                    Success = false,
                    Response = errorChatResponse
                };
            }
        }

        // ---------- helpers ----------

        private static object BuildOpenAIChatRequest(
            List<ChatMessage> messages,
            int maxTokens,
            LLMServiceObj svc,
            IToolsBuilder toolsBuilder,
            string model,
            MLParams mlParams)
        {
            var msgWire = messages.Select(m => new Dictionary<string, object?>
            {
                ["role"] = m.Role,
                ["content"] = m.Content
            }).ToList();

            object? tools = null;
            if (toolsBuilder?.Tools is not null && toolsBuilder.Tools.Any())
            {
                tools = toolsBuilder.Tools.Select(t => new
                {
                    type = "function",
                    function = new
                    {
                        name = t.Function?.Name,
                        description = t.Function?.Description,
                        parameters = t.Function?.Parameters
                    }
                }).ToList();
            }

            return new
            {
                model = string.IsNullOrWhiteSpace(model) ? "gpt-4o-mini" : model,
                messages = msgWire,
                temperature = mlParams?.LlmTemperature ?? 0.2,
                top_p = mlParams?.LlmTopP ?? 1.0,
                max_tokens = maxTokens,
                stream = true,
                tools,
                tool_choice = tools is null ? "none" : "auto"
            };
        }
    }
}

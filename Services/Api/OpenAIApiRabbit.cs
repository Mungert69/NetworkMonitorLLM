// OpenAIApiRabbitApi.cs
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using NetworkMonitor.LLM.Api; // your OpenAIApiRabbit transport
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Utils.Helpers;
using System.Text.Json;

namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    /// ILLMApi over RabbitMQ (OpenAI-compatible server).
    /// Matches OpenAIApi constructor shape; only the transport differs.
    /// </summary>
    public sealed class OpenAIApiRabbitApi : ILLMApi, IDisposable
    {
        private readonly OpenAIApiRabbit _mq;               // Rabbit transport
        private readonly IToolsBuilder _toolsBuilder;
        private readonly ILogger _logger;
        private readonly bool _isXml;
        private readonly MLParams _mlParams;
        private readonly LLMConfig _config;
        private readonly string _modelVersion;
        private readonly string _serviceID;
        private readonly ILLMResponseProcessor _responseProcessor;
        private int _systemPromptCount;
        private string _gptModel = "gpt-4o-mini";

        public int SystemPromptCount => _systemPromptCount;
        public LLMConfig Config => _config;

        // Keep same ctor “shape” as OpenAIApi, but last arg is the Rabbit transport
        public OpenAIApiRabbitApi(
            ILogger logger,
            MLParams mlParams,
            IToolsBuilder toolsBuilder,
            string serviceID,
            ILLMResponseProcessor responseProcessor,
            OpenAIApiRabbit rabbitTransport
        )
        {
            _logger = logger;
            _mlParams = mlParams;
            _gptModel = mlParams.LlmGptModel;
            _toolsBuilder = toolsBuilder;
            _serviceID = serviceID;
            _responseProcessor = responseProcessor;
            _mq = rabbitTransport ?? throw new ArgumentNullException(nameof(rabbitTransport));

            _modelVersion = mlParams.LlmHFModelVersion;
            _isXml = mlParams.XmlFunctionParsing;
            _config = LLMConfigFactory.GetConfig(_modelVersion);
        }

        public void Dispose()
        {
            try { _mq?.Dispose(); } catch { }
        }

        public string WrapFunctionResponse(string name, string funcStr) => funcStr;

        private string PromptFooter() => _mlParams.XmlFunctionParsing ? Config.XmlPromptFooter : "";

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink = false)
        {
            string footer = PromptFooter();
            var systemMessages = _toolsBuilder.GetSystemPrompt(currentTime, serviceObj, "TurboLLM")
                                 ?? new List<ChatMessage>() { ChatMessage.FromSystem("") };

            _systemPromptCount = systemMessages.Count;
            systemMessages[0].Content = (systemMessages[0].Content ?? "") + footer;

            systemMessages.AddRange(NShotPromptFactory.GetPrompt(_serviceID, _mlParams.XmlFunctionParsing, currentTime, serviceObj, Config));
            _systemPromptCount = systemMessages.Count;
            return systemMessages;
        }

        public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj)
            => _toolsBuilder.GetResumeSystemPrompt(currentTime, serviceObj, "TurboLLM");

        public string GetFunctionNamesAsString(string separator = ", ")
            => _toolsBuilder.GetFunctionNamesAsString();

        public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(
            List<ChatMessage> messages,
            int maxTokens,
            LLMServiceObj serviceObj)
        {
            try
            {
                var req = BuildOpenAIChatRequest(messages, maxTokens, serviceObj, _toolsBuilder, _gptModel);

                // Accumulate streaming chunks
                var content = new System.Text.StringBuilder();
                string? finishReason = null;
                string role = "assistant";
                string id = Guid.NewGuid().ToString("N");
                string model = _gptModel;

                await foreach (var chunkJson in _mq.CreateChatCompletionStreamAsync(req))
                {
                    using var je = JsonDocument.Parse(chunkJson);

                    // If the server ever returns a non-stream final object, just adapt it.
                    if (je.RootElement.TryGetProperty("object", out var objEl) &&
                        objEl.GetString() == "chat.completion")
                    {
                        var finalFromServer = JsonSerializer.Deserialize<ChatCompletionCreateResponse>(chunkJson);
                        if (finalFromServer != null)
                        {
                            // Optionally run XML transform
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

                    // Stream chunk style: choices[0].delta.content etc.
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

                // Synthesize a Betalgo ChatCompletionCreateResponse
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
                _logger.LogError($"Exception in CreateCompletionAsync (Rabbit): {ex.Message}");

                var errorChatResponse = new ChatCompletionCreateResponse
                {
                    Id = Guid.NewGuid().ToString(),
                    Model = _gptModel,
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
            string model)
        {
            var msgWire = messages.Select(m => new Dictionary<string, object?>
            {
                ["role"] = m.Role,
                ["content"] = m.Content
            }).ToList();

            // Convert your Tools (if present) to OpenAI wire shape
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
                        parameters = t.Function?.Parameters // already JSON schema in your stack
                    }
                }).ToList();
            }

            return new
            {
                model = svc?.Model ?? model,
                messages = msgWire,
                temperature = svc?.Temperature ?? 0.2,
                top_p = svc?.TopP ?? 1.0,
                max_tokens = maxTokens,
                stream = true,
                tools,
                tool_choice = tools is null ? "none" : "auto"
            };
        }
    }
}

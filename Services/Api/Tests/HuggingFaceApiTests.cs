using System.Collections.Generic;
using System.Reflection;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceApiTests
{
    private readonly Mock<IToolsBuilder> _toolsBuilder = new();
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly MLParams _mlParams;

    public HuggingFaceApiTests()
    {
        _mlParams = new MLParams
        {
            LlmHFModelVersion = "llama_3.2",
            LlmTemp = "0.25",
            LlmHFModelID = "model",
            LlmHFKey = "key",
            LlmHFUrl = "https://example-hf",
            XmlFunctionParsing = true,
            NoNShot = true
        };

        _toolsBuilder.SetupGet(t => t.Tools).Returns(new List<ToolDefinition>());
        _toolsBuilder
            .Setup(t => t.GetSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "HugLLM"))
            .Returns(() => new List<ChatMessage> { ChatMessage.FromSystem("base") });
        _toolsBuilder
            .Setup(t => t.GetResumeSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "HugLLM"))
            .Returns(new List<ChatMessage> { ChatMessage.FromSystem("resume") });
        _toolsBuilder
            .Setup(t => t.GetFunctionNamesAsString(It.IsAny<string>()))
            .Returns("f,g");
    }

    private HuggingFaceApi CreateApi(bool isStream = false)
        => new(_logger.Object, _mlParams, _toolsBuilder.Object, "service", _responseProcessor.Object, isStream);

    [Fact]
    public void WrapFunctionResponse_UsesCurrentConfig()
    {
        _mlParams.LlmUseToolRoleForFunctionResponses = false;
        var api = CreateApi();
        var expected = string.Format(api.Config.FunctionResponse, "tool", "payload");

        var wrapped = api.WrapFunctionResponse("tool", "payload");

        Assert.Equal(expected, wrapped);
    }

    [Fact]
    public void WrapFunctionResponse_IsPassthrough_WhenToolRoleModeEnabled()
    {
        _mlParams.LlmUseToolRoleForFunctionResponses = true;
        var api = CreateApi();

        var wrapped = api.WrapFunctionResponse("tool", "payload");

        Assert.Equal("payload", wrapped);
    }

    [Fact]
    public void GetSystemPrompt_AppendsToolsWrapperAndFooter()
    {
        var api = CreateApi();
        var prompt = api.GetSystemPrompt("now", new LLMServiceObj(), noThink: false);

        Assert.NotEmpty(prompt);
        Assert.Contains("Ensure that any function calls you use align", prompt[0].Content);
        Assert.Contains(api.Config.XmlPromptFooter.Trim().Split('\n')[0], prompt[0].Content);
        Assert.Equal(prompt.Count, api.SystemPromptCount);
    }

    [Fact]
    public void GetResumeSystemPrompt_ReturnsBuilderValue()
    {
        var api = CreateApi();
        var prompt = api.GetResumeSystemPrompt("now", new LLMServiceObj());

        Assert.Single(prompt);
        Assert.Equal("resume", prompt[0].Content);
    }

    [Fact]
    public void GetFunctionNamesAsString_Delegates()
    {
        var api = CreateApi();

        var names = api.GetFunctionNamesAsString(" | ");

        Assert.Equal("f,g", names);
        _toolsBuilder.Verify(t => t.GetFunctionNamesAsString(It.IsAny<string>()), Times.Once());
    }

    [Fact]
    public void BuildPayload_SerializesBetalgoValueTypesAsOpenAIPrimitives()
    {
        _mlParams.LlmHfSupportsFunctionCalling = true;
        var api = CreateApi();
        var messages = new List<ChatMessage>
        {
            ChatMessage.FromUser("hello"),
            new ChatMessage
            {
                Role = "assistant",
                Content = string.Empty,
                ToolCalls = new List<ToolCall>
                {
                    new()
                    {
                        Id = "call_1",
                        Type = "function",
                        FunctionCall = new FunctionCall
                        {
                            Name = "add_host",
                            Arguments = "{\"detail_response\":false}"
                        }
                    }
                }
            },
            ChatMessage.FromTool("{}", "call_1"),
            new("user", new List<MessageContent>
            {
                MessageContent.TextContent("look at this"),
                MessageContent.ImageUrlContent("https://example.com/image.jpg", "high")
            }, null, null, null)
        };

        var convert = typeof(HuggingFaceApi).GetMethod("ConvertMessagesForOpenAIToolMode", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var structuredMessages = (List<Dictionary<string, object?>>)convert.Invoke(api, new object[] { messages })!;

        var buildPayload = typeof(HuggingFaceApi).GetMethod("BuildPayload", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var payload = buildPayload.Invoke(api, new object?[] { messages, 128, null, structuredMessages })!;

        var json = JsonConvert.SerializeObject(payload, Formatting.None, new JsonSerializerSettings
        {
            ContractResolver = new CamelCasePropertyNamesContractResolver(),
            NullValueHandling = NullValueHandling.Ignore
        });

        Assert.Contains("\"role\":\"user\"", json);
        Assert.Contains("\"role\":\"assistant\"", json);
        Assert.Contains("\"role\":\"tool\"", json);
        Assert.Contains("\"type\":\"function\"", json);
        Assert.Contains("\"detail\":\"high\"", json);
        Assert.DoesNotContain("\"role\":{\"value\"", json);
        Assert.DoesNotContain("\"type\":{\"value\"", json);
        Assert.DoesNotContain("\"detail\":{\"value\"", json);
    }
}

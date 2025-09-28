using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
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
        var api = CreateApi();
        var expected = string.Format(api.Config.FunctionResponse, "tool", "payload");

        var wrapped = api.WrapFunctionResponse("tool", "payload");

        Assert.Equal(expected, wrapped);
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
}

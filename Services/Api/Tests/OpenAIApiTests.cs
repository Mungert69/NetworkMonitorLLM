using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class OpenAIApiTests
{
    private readonly Mock<IToolsBuilder> _toolsBuilder = new();
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly MLParams _mlParams;

    public OpenAIApiTests()
    {
        _mlParams = new MLParams
        {
            LlmGptModel = "custom-model",
            LlmHFModelVersion = "llama_3.2",
            XmlFunctionParsing = true,
            NoNShot = true
        };

        _toolsBuilder.SetupGet(t => t.Tools).Returns(new List<ToolDefinition>());
        _toolsBuilder
            .Setup(t => t.GetSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "TurboLLM"))
            .Returns(() => new List<ChatMessage> { ChatMessage.FromSystem("base") });
        _toolsBuilder
            .Setup(t => t.GetResumeSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "TurboLLM"))
            .Returns(new List<ChatMessage> { ChatMessage.FromSystem("resume") });
        _toolsBuilder
            .Setup(t => t.GetFunctionNamesAsString(It.IsAny<string>()))
            .Returns("space");
    }

    private OpenAIApi CreateApi() =>
        new(_logger.Object, _mlParams, _toolsBuilder.Object, "service", _responseProcessor.Object, null!);

    [Fact]
    public void GetSystemPrompt_AppendsXmlFooterWhenEnabled()
    {
        var api = CreateApi();
        var prompt = api.GetSystemPrompt("now", new LLMServiceObj(), noThink: false);

        Assert.Contains(api.Config.XmlPromptFooter.Trim().Split('\n')[0], prompt[0].Content);
        Assert.Equal(prompt.Count, api.SystemPromptCount);
    }

    [Fact]
    public void WrapFunctionResponse_IsPassthrough()
    {
        var api = CreateApi();
        var payload = api.WrapFunctionResponse("tool", "output");

        Assert.Equal("output", payload);
    }

    [Fact]
    public void GetFunctionNamesAsString_Delegates()
    {
        var api = CreateApi();
        var names = api.GetFunctionNamesAsString("|");

        Assert.Equal("space", names);
    }
}

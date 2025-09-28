using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceRabbitApiTests
{
    private readonly Mock<IToolsBuilder> _toolsBuilder = new();
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly Mock<IRabbitRepo> _rabbitRepo = new();
    private readonly MLParams _mlParams;
    private readonly SystemParams _systemParams;
    private readonly RabbitTransport _transport;

    public HuggingFaceRabbitApiTests()
    {
        _mlParams = new MLParams
        {
            LlmHFModelVersion = "qwen_3",
            LlmSpaceModelID = "space-model",
            XmlFunctionParsing = true,
            NoNShot = true
        };

        _systemParams = new SystemParams
        {
            ThisSystemUrl = new SystemUrl
            {
                RabbitHostName = "localhost",
                RabbitUserName = "user",
                RabbitPassword = "pass",
                RabbitPort = 5672
            },
            RabbitRoutingKey = "rk"
        };

        _transport = new RabbitTransport(_rabbitRepo.Object, _systemParams.ThisSystemUrl, _systemParams.RabbitRoutingKey, _logger.Object);

        _toolsBuilder.SetupGet(t => t.Tools).Returns(new List<ToolDefinition>());
        _toolsBuilder
            .Setup(t => t.GetSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "HugRabbit"))
            .Returns(() => new List<ChatMessage> { ChatMessage.FromSystem("base") });
        _toolsBuilder
            .Setup(t => t.GetResumeSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "HugRabbit"))
            .Returns(new List<ChatMessage> { ChatMessage.FromSystem("resume") });
        _toolsBuilder
            .Setup(t => t.GetFunctionNamesAsString(It.IsAny<string>()))
            .Returns("alpha,beta");
    }

    private HuggingFaceRabbitApi CreateApi() =>
        new(_logger.Object, _mlParams, _toolsBuilder.Object, "service", _responseProcessor.Object, _transport);

    [Fact]
    public void GetSystemPrompt_IncludesFooterAndNoThink()
    {
        var api = CreateApi();
        var prompt = api.GetSystemPrompt("now", new LLMServiceObj(), noThink: true);

        Assert.Contains("# Tools", prompt[0].Content);
        Assert.Contains(api.Config.NoThinkToken, prompt[0].Content);
    }

    [Fact]
    public void GetResumeSystemPrompt_ReturnsBuilderContent()
    {
        var api = CreateApi();
        var prompt = api.GetResumeSystemPrompt("now", new LLMServiceObj());

        Assert.Single(prompt);
        Assert.Equal("resume", prompt[0].Content);
    }

    [Fact]
    public void WrapFunctionResponse_UsesConfigTemplate()
    {
        var api = CreateApi();
        var expected = string.Format(api.Config.FunctionResponse, "tool", "payload");

        var result = api.WrapFunctionResponse("tool", "payload");

        Assert.Equal(expected, result);
    }

    [Fact]
    public void GetFunctionNamesAsString_Delegates()
    {
        var api = CreateApi();
        var names = api.GetFunctionNamesAsString("/");

        Assert.Equal("alpha,beta", names);
    }
}

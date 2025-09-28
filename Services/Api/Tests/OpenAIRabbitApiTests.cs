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

public class OpenAIRabbitApiTests
{
    private readonly Mock<IToolsBuilder> _toolsBuilder = new();
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly Mock<IRabbitRepo> _rabbitRepo = new();
    private readonly MLParams _mlParams;
    private readonly SystemParams _systemParams;
    private readonly RabbitTransport _transport;

    public OpenAIRabbitApiTests()
    {
        _mlParams = new MLParams
        {
            LlmHFModelVersion = "llama_3.2",
            LlmSpaceModelID = "space-model",
            XmlFunctionParsing = true,
            NoNShot = true
        };

        _systemParams = new SystemParams
        {
            RabbitRoutingKey = "rk",
            ThisSystemUrl = new SystemUrl
            {
                RabbitHostName = "localhost",
                RabbitUserName = "user",
                RabbitPassword = "pass",
                RabbitPort = 5672
            }
        };

        _transport = new RabbitTransport(_rabbitRepo.Object, _systemParams.ThisSystemUrl, _systemParams.RabbitRoutingKey, _logger.Object);

        _toolsBuilder.SetupGet(t => t.Tools).Returns(new List<ToolDefinition>());
        _toolsBuilder
            .Setup(t => t.GetSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "TurboLLM"))
            .Returns(() => new List<ChatMessage> { ChatMessage.FromSystem("base") });
        _toolsBuilder
            .Setup(t => t.GetResumeSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "TurboLLM"))
            .Returns(new List<ChatMessage> { ChatMessage.FromSystem("resume") });
        _toolsBuilder
            .Setup(t => t.GetFunctionNamesAsString(It.IsAny<string>()))
            .Returns("names");
    }

    private OpenAIRabbitApi CreateApi() =>
        new(_logger.Object, _mlParams, _toolsBuilder.Object, "service", _responseProcessor.Object, _transport);

    [Fact]
    public void GetSystemPrompt_AddsXmlFooter()
    {
        var api = CreateApi();
        var prompt = api.GetSystemPrompt("now", new LLMServiceObj(), noThink: false);

        Assert.Contains(api.Config.XmlPromptFooter.Trim().Split('\n')[0], prompt[0].Content);
    }

    [Fact]
    public void WrapFunctionResponse_IsPassthrough()
    {
        var api = CreateApi();
        var value = api.WrapFunctionResponse("name", "data");

        Assert.Equal("data", value);
    }

    [Fact]
    public void GetFunctionNamesAsString_Delegates()
    {
        var api = CreateApi();
        var names = api.GetFunctionNamesAsString(",");

        Assert.Equal("names", names);
    }
}

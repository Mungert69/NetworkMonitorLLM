using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LLMApiFactoryTests
{
    private readonly LLMApiFactory _factory = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly Mock<IToolsBuilder> _toolsBuilder = new();
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<IRabbitRepo> _rabbitRepo = new();
    private readonly SystemParams _systemParams;
    private readonly MLParams _mlParams;

    public LLMApiFactoryTests()
    {
        _mlParams = new MLParams
        {
            LlmHFModelVersion = "blank",
            LlmHFModelID = "hf-model",
            LlmHFKey = "key",
            LlmHFUrl = "https://example",
            LlmTemp = "0.1",
            LlmGptModel = "custom",
            NoNShot = true
        };

        _toolsBuilder.SetupGet(t => t.Tools).Returns(new List<ToolDefinition>());
        _responseProcessor.SetupGet(r => r.RabbitRepo).Returns(_rabbitRepo.Object);

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
    }

    [Theory]
    [InlineData("OpenAI", typeof(OpenAIApi))]
    [InlineData("HuggingFace", typeof(HuggingFaceApi))]
    [InlineData("OpenAIRabbit", typeof(OpenAIRabbitApi))]
    [InlineData("HuggingFaceRabbit", typeof(HuggingFaceRabbitApi))]
    public void CreateApi_ReturnsExpectedImplementation(string provider, System.Type expectedType)
    {
        var api = _factory.CreateApi(
            _logger.Object,
            _mlParams,
            _toolsBuilder.Object,
            "svc",
            _responseProcessor.Object,
            _systemParams,
            provider,
            null!);

        Assert.IsType(expectedType, api);
        if (api is System.IDisposable disposable) disposable.Dispose();
    }

    [Fact]
    public void CreateApi_UnknownProvider_Throws()
    {
        Assert.Throws<System.ArgumentException>(() => _factory.CreateApi(
            _logger.Object,
            _mlParams,
            _toolsBuilder.Object,
            "svc",
            _responseProcessor.Object,
            _systemParams,
            "Unknown",
            null!));
    }
}

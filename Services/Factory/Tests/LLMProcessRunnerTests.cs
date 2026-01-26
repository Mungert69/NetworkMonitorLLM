using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Coordinator;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LLMProcessRunnerTests
{
    private LLMProcessRunner CreateRunner(LLMServiceObj startServiceObj, MLParams mlParams)
    {
        var logger = new Mock<ILogger<LLMProcessRunner>>();
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo).Returns(Mock.Of<IRabbitRepo>());
        var systemParams = new SystemParams
        {
            ServiceID = "monitor",
            ServiceAuthKey = "auth"
        };
        var cpuUsageMonitor = new Mock<ICpuUsageMonitor>();
        cpuUsageMonitor.Setup(m => m.IsMemoryAvailable(It.IsAny<int>())).Returns(true);
        var queryCoordinator = Mock.Of<IQueryCoordinator>();
        var systemPromptWriter = Mock.Of<ISystemPromptWriter>();

        return new LLMProcessRunner(
            logger.Object,
            responseProcessor.Object,
            systemParams,
            mlParams,
            startServiceObj,
            new SemaphoreSlim(1, 1),
            Mock.Of<IAudioGenerator>(),
            cpuUsageMonitor.Object,
            queryCoordinator,
            systemPromptWriter);
    }

    [Fact]
    public async Task SendInputAndGetResponse_WhenStartAudio_Throws()
    {
        var mlParams = new MLParams
        {
            LlmUserPromptTimeout = 5,
            LlmNoInitMessage = true
        };
        var startServiceObj = new LLMServiceObj
        {
            SessionId = "session-1",
            UserInfo = new UserInfo { AccountType = "Default" }
        };
        var runner = CreateRunner(startServiceObj, mlParams);

        var serviceObj = new LLMServiceObj(startServiceObj)
        {
            UserInput = "<|START_AUDIO|>"
        };

        var ex = await Assert.ThrowsAsync<Exception>(() => runner.SendInputAndGetResponse(serviceObj));
        Assert.Contains("Audio is not available", ex.Message);
    }

    [Fact]
    public async Task SendInputAndGetResponse_WhenSessionMissing_Throws()
    {
        var mlParams = new MLParams
        {
            LlmUserPromptTimeout = 5,
            LlmNoInitMessage = true
        };
        var startServiceObj = new LLMServiceObj
        {
            SessionId = "session-1",
            UserInfo = new UserInfo { AccountType = "Default" }
        };
        var runner = CreateRunner(startServiceObj, mlParams);

        var serviceObj = new LLMServiceObj(startServiceObj)
        {
            UserInput = "hello",
            SessionId = "missing-session"
        };

        var ex = await Assert.ThrowsAsync<Exception>(() => runner.SendInputAndGetResponse(serviceObj));
        Assert.Contains("No Assistant found for sessionId", ex.Message);
    }
}

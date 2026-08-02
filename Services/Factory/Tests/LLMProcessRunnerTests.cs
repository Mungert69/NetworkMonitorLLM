using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
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
    private static (LLMProcessRunner Runner, Mock<ILLMResponseProcessor> ResponseProcessor) CreateRunner(
        LLMServiceObj startServiceObj,
        MLParams mlParams,
        List<ChatMessage>? history = null)
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

        var runner = new LLMProcessRunner(
             logger.Object,
             responseProcessor.Object,
             systemParams,
             mlParams,
             startServiceObj,
             new SemaphoreSlim(1, 1),
             Mock.Of<IAudioGenerator>(),
             cpuUsageMonitor.Object,
             queryCoordinator,
             systemPromptWriter,
             history ?? new List<ChatMessage>());

        return (runner, responseProcessor);
    }

    [Fact]
    public async Task SendInputAndGetResponse_WhenAudioCommands_ToggleCreateAudio()
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
        var (runner, responseProcessor) = CreateRunner(startServiceObj, mlParams);

        var startAudioObj = new LLMServiceObj(startServiceObj)
        {
            UserInput = "<|START_AUDIO|>"
        };

        await runner.SendInputAndGetResponse(startAudioObj);
        Assert.True(GetCreateAudio(runner));

        var stopAudioObj = new LLMServiceObj(startServiceObj)
        {
            UserInput = "<|STOP_AUDIO|>"
        };

        await runner.SendInputAndGetResponse(stopAudioObj);
        Assert.False(GetCreateAudio(runner));
        responseProcessor.Verify(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>()), Times.Never);
    }

    [Fact]
    public async Task SendInputAndGetResponse_WhenSessionMissing_SendsErrorAndDoesNotThrow()
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
        var (runner, responseProcessor) = CreateRunner(startServiceObj, mlParams);
        responseProcessor
            .Setup(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask);

        var serviceObj = new LLMServiceObj(startServiceObj)
        {
            UserInput = "hello",
            SessionId = "missing-session"
        };

        await runner.SendInputAndGetResponse(serviceObj);

        responseProcessor.Verify(
            r => r.ProcessLLMOutputError(It.Is<LLMServiceObj>(m =>
                m.LlmMessage.Contains("No Assistant found for sessionId", StringComparison.Ordinal))),
            Times.Once);
    }

    [Fact]
    public void Constructor_PreservesLoadedHistory()
    {
        var history = new List<ChatMessage> { ChatMessage.FromUser("saved user message") };
        var startServiceObj = new LLMServiceObj
        {
            SessionId = "session-1",
            UserInfo = new UserInfo { AccountType = "Default" }
        };

        _ = CreateRunner(startServiceObj, new MLParams(), history);

        Assert.Single(history);
        Assert.Equal("saved user message", history[0].Content);
    }

    [Fact]
    public void SetLocalLlmContext_MarksExistingContextForOneTimeRestore()
    {
        var startServiceObj = new LLMServiceObj
        {
            SessionId = "session-1",
            UserInfo = new UserInfo { AccountType = "Default" }
        };
        var (runner, _) = CreateRunner(startServiceObj, new MLParams());

        runner.SetLocalLlmContext("<|user|>prior question<|assistant|>prior answer");

        Assert.Equal("<|user|>prior question<|assistant|>prior answer", runner.LocalLlmContext);
        var restoreField = typeof(LLMProcessRunner).GetField("_restoreLocalLlmContext", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(restoreField);
        Assert.True((bool)restoreField!.GetValue(runner)!);
    }

    private static bool GetCreateAudio(LLMProcessRunner runner)
    {
        var field = typeof(LLMProcessRunner).GetField("_createAudio", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return (bool)field!.GetValue(runner)!;
    }
}

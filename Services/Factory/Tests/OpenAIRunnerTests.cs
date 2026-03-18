using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Coordinator;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class OpenAIRunnerTests
{
    private sealed class FakeToolsBuilder : IToolsBuilder
    {
        public List<ToolDefinition> Tools { get; } = new();

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType) =>
            new() { ChatMessage.FromSystem("") };

        public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType) =>
            new() { ChatMessage.FromSystem("") };

        public string GetFunctionNamesAsString(string separator = ", ") => string.Empty;
    }

    private sealed class FakeLlmApi : ILLMApi
    {
        public LLMConfig Config { get; } = new();
        public int SystemPromptCount { get; } = 1;

        public Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(
            List<ChatMessage> messages,
            int maxTokens,
            LLMServiceObj serviceObj)
        {
            return Task.FromResult(new ChatCompletionCreateResponseSuccess
            {
                Success = true,
                Response = new ChatCompletionCreateResponse
                {
                    Choices = new List<ChatChoiceResponse>()
                }
            });
        }

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink = false) =>
            new() { ChatMessage.FromSystem("") };

        public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj) =>
            new() { ChatMessage.FromSystem("") };

        public string GetFunctionNamesAsString(string separator = ", ") => string.Empty;

        public string WrapFunctionResponse(string name, string funcStr) => funcStr;
    }

    [Fact]
    public async Task SendInputAndGetResponse_WhenCompletionHasNoChoices_EmitsError()
    {
        var logger = new Mock<ILogger<OpenAIRunner>>();
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo).Returns(Mock.Of<NetworkMonitor.Objects.Repository.IRabbitRepo>());
        responseProcessor.Setup(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask);
        var capturedMessages = new List<string>();
        responseProcessor.Setup(r => r.ProcessLLMOutput(It.IsAny<LLMServiceObj>()))
            .Callback<LLMServiceObj>(obj => capturedMessages.Add(obj.LlmMessage ?? string.Empty))
            .Returns(Task.CompletedTask);
        responseProcessor.Setup(r => r.UpdateTokensUsed(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask);

        var toolsFactory = new Mock<IToolsBuilderFactory>();
        toolsFactory.Setup(t => t.Create(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<string>()))
            .Returns(new FakeToolsBuilder());

        var mlParams = new MLParams
        {
            LlmProvider = "OpenAI",
            LlmOpenAICtxSize = 4096,
            LlmCtxRatio = 4,
            MaxFunctionCallsInARow = 3
        };
        var systemParams = new SystemParams
        {
            ServiceID = "monitor",
            ServiceAuthKey = "auth"
        };

        var serviceObj = new LLMServiceObj
        {
            UserInput = "hello",
            SessionId = "session-1",
            RequestSessionId = "req-1",
            LLMRunnerType = "TurboLLM",
            IsSystemLlm = false,
            SourceLlm = "monitor",
            DestinationLlm = "expert",
            UserInfo = new UserInfo { AccountType = "Default" }
        };

        var runner = new OpenAIRunner(
            logger.Object,
            responseProcessor.Object,
            null!,
            systemParams,
            mlParams,
            serviceObj,
            null,
            Mock.Of<IAudioGenerator>(),
            false,
            new List<ChatMessage>(),
            Mock.Of<IQueryCoordinator>(),
            toolsFactory.Object);

        var llmApiField = typeof(OpenAIRunner).GetField("_llmApi", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(llmApiField);
        llmApiField!.SetValue(runner, new FakeLlmApi());

        await runner.SendInputAndGetResponse(serviceObj);

        responseProcessor.Verify(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>()), Times.Once);
    }

    [Fact]
    public async Task SendInputAndGetResponse_WhenCompletionFailsWithNoError_EmitsError()
    {
        var logger = new Mock<ILogger<OpenAIRunner>>();
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo).Returns(Mock.Of<NetworkMonitor.Objects.Repository.IRabbitRepo>());
        responseProcessor.Setup(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask);
        var capturedMessages = new List<string>();
        responseProcessor.Setup(r => r.ProcessLLMOutput(It.IsAny<LLMServiceObj>()))
            .Callback<LLMServiceObj>(obj => capturedMessages.Add(obj.LlmMessage ?? string.Empty))
            .Returns(Task.CompletedTask);
        responseProcessor.Setup(r => r.UpdateTokensUsed(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask);

        var toolsFactory = new Mock<IToolsBuilderFactory>();
        toolsFactory.Setup(t => t.Create(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<string>()))
            .Returns(new FakeToolsBuilder());

        var mlParams = new MLParams
        {
            LlmProvider = "OpenAI",
            LlmOpenAICtxSize = 4096,
            LlmCtxRatio = 4,
            MaxFunctionCallsInARow = 3
        };
        var systemParams = new SystemParams
        {
            ServiceID = "monitor",
            ServiceAuthKey = "auth"
        };

        var serviceObj = new LLMServiceObj
        {
            UserInput = "hello",
            SessionId = "session-1",
            RequestSessionId = "req-1",
            LLMRunnerType = "TurboLLM",
            IsSystemLlm = false,
            SourceLlm = "monitor",
            DestinationLlm = "expert",
            UserInfo = new UserInfo { AccountType = "Default" }
        };

        var runner = new OpenAIRunner(
            logger.Object,
            responseProcessor.Object,
            null!,
            systemParams,
            mlParams,
            serviceObj,
            null,
            Mock.Of<IAudioGenerator>(),
            false,
            new List<ChatMessage>(),
            Mock.Of<IQueryCoordinator>(),
            toolsFactory.Object);

        var llmApiField = typeof(OpenAIRunner).GetField("_llmApi", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(llmApiField);
        llmApiField!.SetValue(runner, new FailingLlmApi());

        await runner.SendInputAndGetResponse(serviceObj);

        responseProcessor.Verify(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>()), Times.Once);
    }

    [Theory]
    [InlineData("length", "truncated")]
    [InlineData("content_filter", "blocked")]
    public async Task SendInputAndGetResponse_WhenFinishReasonIsNotStop_EmitsNotice(string finishReason, string expectedFragment)
    {
        var logger = new Mock<ILogger<OpenAIRunner>>();
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo).Returns(Mock.Of<NetworkMonitor.Objects.Repository.IRabbitRepo>());
        responseProcessor.Setup(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask);
        var capturedMessages = new List<string>();
        responseProcessor.Setup(r => r.ProcessLLMOutput(It.IsAny<LLMServiceObj>()))
            .Callback<LLMServiceObj>(obj => capturedMessages.Add(obj.LlmMessage ?? string.Empty))
            .Returns(Task.CompletedTask);
        responseProcessor.Setup(r => r.UpdateTokensUsed(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask);

        var toolsFactory = new Mock<IToolsBuilderFactory>();
        toolsFactory.Setup(t => t.Create(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<string>()))
            .Returns(new FakeToolsBuilder());

        var mlParams = new MLParams
        {
            LlmProvider = "OpenAI",
            LlmOpenAICtxSize = 4096,
            LlmCtxRatio = 4,
            MaxFunctionCallsInARow = 3
        };
        var systemParams = new SystemParams
        {
            ServiceID = "monitor",
            ServiceAuthKey = "auth"
        };

        var serviceObj = new LLMServiceObj
        {
            UserInput = "hello",
            SessionId = "session-1",
            RequestSessionId = "req-1",
            LLMRunnerType = "TurboLLM",
            IsSystemLlm = false,
            SourceLlm = "monitor",
            DestinationLlm = "expert",
            UserInfo = new UserInfo { AccountType = "Default" }
        };

        var runner = new OpenAIRunner(
            logger.Object,
            responseProcessor.Object,
            null!,
            systemParams,
            mlParams,
            serviceObj,
            null,
            Mock.Of<IAudioGenerator>(),
            false,
            new List<ChatMessage>(),
            Mock.Of<IQueryCoordinator>(),
            toolsFactory.Object);

        var llmApiField = typeof(OpenAIRunner).GetField("_llmApi", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(llmApiField);
        llmApiField!.SetValue(runner, new FinishReasonLlmApi(finishReason));

        await runner.SendInputAndGetResponse(serviceObj);

        Assert.Contains(capturedMessages, msg => msg.Contains(expectedFragment));
    }

    [Fact]
    public async Task ReplayHistory_HoldsRunnerLockWhileSendingHistoryDisplay()
    {
        var logger = new Mock<ILogger<OpenAIRunner>>();
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo).Returns(Mock.Of<NetworkMonitor.Objects.Repository.IRabbitRepo>());
        responseProcessor.Setup(r => r.ProcessLLMOutput(It.IsAny<LLMServiceObj>())).Returns(Task.CompletedTask);
        responseProcessor.Setup(r => r.ProcessLLMOutputError(It.IsAny<LLMServiceObj>())).Returns(Task.CompletedTask);
        responseProcessor.Setup(r => r.UpdateTokensUsed(It.IsAny<LLMServiceObj>())).Returns(Task.CompletedTask);

        var toolsFactory = new Mock<IToolsBuilderFactory>();
        toolsFactory.Setup(t => t.Create(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<string>()))
            .Returns(new FakeToolsBuilder());

        var mlParams = new MLParams
        {
            LlmProvider = "OpenAI",
            LlmOpenAICtxSize = 4096,
            LlmCtxRatio = 4,
            MaxFunctionCallsInARow = 3
        };
        var systemParams = new SystemParams
        {
            ServiceID = "monitor",
            ServiceAuthKey = "auth"
        };

        var history = new List<ChatMessage>
        {
            ChatMessage.FromSystem("sys"),
            ChatMessage.FromAssistant("old reply")
        };

        var serviceObj = new LLMServiceObj
        {
            UserInput = "<|REPLAY_HISTORY|>",
            SessionId = "session-1",
            RequestSessionId = "req-1",
            LLMRunnerType = "TurboLLM",
            IsSystemLlm = false,
            SourceLlm = "monitor",
            DestinationLlm = "expert",
            UserInfo = new UserInfo { AccountType = "Default" }
        };

        var runner = new OpenAIRunner(
            logger.Object,
            responseProcessor.Object,
            null!,
            systemParams,
            mlParams,
            serviceObj,
            null,
            Mock.Of<IAudioGenerator>(),
            false,
            history,
            Mock.Of<IQueryCoordinator>(),
            toolsFactory.Object);

        var llmApiField = typeof(OpenAIRunner).GetField("_llmApi", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(llmApiField);
        llmApiField!.SetValue(runner, new FakeLlmApi());

        var sendHistoryStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSendHistory = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        runner.SendHistory += async _ =>
        {
            sendHistoryStarted.TrySetResult(true);
            await releaseSendHistory.Task;
        };

        var replayTask = runner.SendInputAndGetResponse(serviceObj);
        await sendHistoryStarted.Task;

        var normalMessage = new LLMServiceObj
        {
            UserInput = "hello",
            SessionId = "session-1",
            RequestSessionId = "req-1",
            LLMRunnerType = "TurboLLM",
            IsSystemLlm = false,
            SourceLlm = "monitor",
            DestinationLlm = "expert",
            UserInfo = new UserInfo { AccountType = "Default" }
        };

        var normalTask = runner.SendInputAndGetResponse(normalMessage);
        await Task.Delay(100);
        Assert.False(normalTask.IsCompleted, "Normal input should wait while history display send is in progress.");

        releaseSendHistory.TrySetResult(true);
        await replayTask;
        await normalTask;
    }

    private sealed class FailingLlmApi : ILLMApi
    {
        public LLMConfig Config { get; } = new();
        public int SystemPromptCount { get; } = 1;

        public Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(
            List<ChatMessage> messages,
            int maxTokens,
            LLMServiceObj serviceObj)
        {
            return Task.FromResult(new ChatCompletionCreateResponseSuccess
            {
                Success = false,
                Response = new ChatCompletionCreateResponse()
            });
        }

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink = false) =>
            new() { ChatMessage.FromSystem("") };

        public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj) =>
            new() { ChatMessage.FromSystem("") };

        public string GetFunctionNamesAsString(string separator = ", ") => string.Empty;

        public string WrapFunctionResponse(string name, string funcStr) => funcStr;
    }

    private sealed class FinishReasonLlmApi : ILLMApi
    {
        private readonly string _finishReason;

        public FinishReasonLlmApi(string finishReason)
        {
            _finishReason = finishReason;
        }

        public LLMConfig Config { get; } = new();
        public int SystemPromptCount { get; } = 1;

        public Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(
            List<ChatMessage> messages,
            int maxTokens,
            LLMServiceObj serviceObj)
        {
            return Task.FromResult(new ChatCompletionCreateResponseSuccess
            {
                Success = true,
                Response = new ChatCompletionCreateResponse
                {
                    Choices = new List<ChatChoiceResponse>
                    {
                        new ChatChoiceResponse
                        {
                            FinishReason = _finishReason,
                            Message = new ChatMessage
                            {
                                Role = "assistant",
                                Content = ""
                            }
                        }
                    }
                }
            });
        }

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink = false) =>
            new() { ChatMessage.FromSystem("") };

        public List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj) =>
            new() { ChatMessage.FromSystem("") };

        public string GetFunctionNamesAsString(string separator = ", ") => string.Empty;

        public string WrapFunctionResponse(string name, string funcStr) => funcStr;
    }
}

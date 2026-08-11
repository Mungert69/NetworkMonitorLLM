using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Coordinator;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class OpenAIRunnerTests
{
    [Fact]
    public void CountTokensForMessage_CountsToolCallArgumentsButNotToolName()
    {
        const string arguments = "{\"host\":\"example.net\",\"port\":443}";
        var message = new ChatMessage
        {
            Role = "assistant",
            ToolCalls = new List<ToolCall>
            {
                new()
                {
                    Type = "function",
                    FunctionCall = new FunctionCall
                    {
                        Name = "a_tool_name_that_must_not_affect_the_budget",
                        Arguments = arguments
                    }
                }
            }
        };

        var method = typeof(OpenAIRunner).GetMethod(
            "CountTokensForMessage",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        var tokenCount = Assert.IsType<int>(method!.Invoke(null, new object[] { message }));

        Assert.Equal(TokenizerGpt3.TokenCount(arguments), tokenCount);
    }

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

    [Fact]
    public async Task SendInputAndGetResponse_WhenStopCompletionIsEmpty_DoesNotPersistBlankAssistantMessage()
    {
        var history = new List<ChatMessage>();
        var runner = CreateRunner(new MLParams());
        var llmApiField = typeof(OpenAIRunner).GetField("_llmApi", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(llmApiField);
        llmApiField!.SetValue(runner, new FinishReasonLlmApi("stop"));

        var historyField = typeof(OpenAIRunner).GetField("_history", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(historyField);
        historyField!.SetValue(runner, history);

        await runner.SendInputAndGetResponse(CreateServiceObject("hello"));

        Assert.DoesNotContain(history, message =>
            message.Role == "assistant" &&
            string.IsNullOrWhiteSpace(message.Content) &&
            !(message.ToolCalls?.Any() ?? false));
    }

    [Fact]
    public void SanitizeMessagesForCompletion_RemovesOnlyEmptyAssistantMessagesWithoutToolCalls()
    {
        var runner = CreateRunner(new MLParams());
        var messages = new List<ChatMessage>
        {
            ChatMessage.FromAssistant(""),
            new ChatMessage
            {
                Role = "assistant",
                Content = "",
                ToolCalls = new List<ToolCall> { new() { Id = "call-1", Type = "function" } }
            }
        };

        var sanitizeMethod = typeof(OpenAIRunner).GetMethod(
            "SanitizeMessagesForCompletion",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(sanitizeMethod);
        sanitizeMethod!.Invoke(runner, new object[] { messages });

        Assert.Single(messages);
        Assert.Equal("call-1", messages[0].ToolCalls![0].Id);
    }

    [Fact]
    public void NormalizeSystemMessagesForCompletion_WhenLaterSystemMessagesAreDisabled_ConvertsOnlyLaterMessages()
    {
        var runner = CreateRunner(new MLParams { LlmAllowSystemMessagesAfterFirst = false });
        var messages = new List<ChatMessage>
        {
            ChatMessage.FromSystem("primary prompt"),
            ChatMessage.FromSystem("second primary prompt"),
            ChatMessage.FromUser("hello"),
            ChatMessage.FromSystem("RAG result"),
            ChatMessage.FromAssistant("answer"),
            ChatMessage.FromSystem("resume context")
        };

        var normalizeMethod = typeof(OpenAIRunner).GetMethod(
            "NormalizeSystemMessagesForCompletion",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(normalizeMethod);
        normalizeMethod!.Invoke(runner, new object[] { messages });

        Assert.Equal("system", messages[0].Role);
        Assert.Equal("system", messages[1].Role);
        Assert.Equal("user", messages[3].Role);
        Assert.Equal("[Runtime guidance]\nRAG result", messages[3].Content);
        Assert.Equal("user", messages[5].Role);
        Assert.Equal("[Runtime guidance]\nresume context", messages[5].Content);
    }

    [Fact]
    public void NormalizeSystemMessagesForCompletion_WhenLaterSystemMessagesAreAllowed_LeavesHistoryUnchanged()
    {
        var runner = CreateRunner(new MLParams { LlmAllowSystemMessagesAfterFirst = true });
        var messages = new List<ChatMessage>
        {
            ChatMessage.FromSystem("primary prompt"),
            ChatMessage.FromUser("hello"),
            ChatMessage.FromSystem("RAG result")
        };

        var normalizeMethod = typeof(OpenAIRunner).GetMethod(
            "NormalizeSystemMessagesForCompletion",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(normalizeMethod);
        normalizeMethod!.Invoke(runner, new object[] { messages });

        Assert.Equal("system", messages[2].Role);
        Assert.Equal("RAG result", messages[2].Content);
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
    public void TruncateTokens_PreservesHead_RespectsBudget_AndRemovesOrphans()
    {
        var logger = new Mock<ILogger<OpenAIRunner>>();
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo).Returns(Mock.Of<NetworkMonitor.Objects.Repository.IRabbitRepo>());

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
            SessionId = "session-truncate-1",
            RequestSessionId = "req-truncate-1",
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
        llmApiField!.SetValue(runner, new TwoHeadLlmApi());

        var promptTokensField = typeof(OpenAIRunner).GetField("_promptTokens", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(promptTokensField);
        promptTokensField!.SetValue(runner, 12);

        var history = new List<ChatMessage>
        {
            ChatMessage.FromSystem("system head keep"),
            ChatMessage.FromSystem("n-shot head keep"),
            ChatMessage.FromUser("old user message one one one one one one one one one"),
            new ChatMessage
            {
                Role = "assistant",
                Content = "assistant calling tool for old context",
                ToolCalls = new List<ToolCall>
                {
                    new ToolCall
                    {
                        Id = "call-1",
                        Type = "function",
                        FunctionCall = new FunctionCall
                        {
                            Name = "lookup",
                            Arguments = "{\"key\":\"value\"}"
                        }
                    }
                }
            },
            new ChatMessage
            {
                Role = "tool",
                ToolCallId = "call-1",
                Content = "tool response payload payload payload payload payload"
            },
            ChatMessage.FromUser("old user message two two two two two two two"),
            new ChatMessage
            {
                Role = "tool",
                ToolCallId = "orphan-call",
                Content = "orphan tool payload must be removed"
            },
            ChatMessage.FromAssistant("latest assistant message kept when possible")
        };

        var truncateMethod = typeof(OpenAIRunner).GetMethod("TruncateTokens", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(truncateMethod);
        truncateMethod!.Invoke(runner, new object[] { history, serviceObj });

        Assert.True(history.Count >= 2);
        Assert.Equal("system", history[0].Role);
        Assert.Equal("system", history[1].Role);

        Assert.DoesNotContain(history, m => m.Role == "tool" && m.ToolCallId == "orphan-call");

        var calculateMethod = typeof(OpenAIRunner).GetMethod("CalculateTokens", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(calculateMethod);
        var totalTokens = (int)calculateMethod!.Invoke(runner, new object[] { history })!;
        Assert.True(totalTokens <= 12);
    }

    private static OpenAIRunner CreateRunner(MLParams mlParams)
    {
        mlParams.LlmProvider = "OpenAI";
        mlParams.LlmOpenAICtxSize = 4096;
        mlParams.LlmCtxRatio = 4;

        var logger = new Mock<ILogger<OpenAIRunner>>();
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo)
            .Returns(Mock.Of<NetworkMonitor.Objects.Repository.IRabbitRepo>());

        var toolsFactory = new Mock<IToolsBuilderFactory>();
        toolsFactory.Setup(t => t.Create(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<string>()))
            .Returns(new FakeToolsBuilder());

        var serviceObj = CreateServiceObject("hello");

        return new OpenAIRunner(
            logger.Object,
            responseProcessor.Object,
            null!,
            new SystemParams { ServiceID = "monitor", ServiceAuthKey = "auth" },
            mlParams,
            serviceObj,
            null,
            Mock.Of<IAudioGenerator>(),
            false,
            new List<ChatMessage>(),
            Mock.Of<IQueryCoordinator>(),
            toolsFactory.Object);
    }

    private static LLMServiceObj CreateServiceObject(string userInput)
    {
        return new LLMServiceObj
        {
            UserInput = userInput,
            SessionId = "session-normalize-1",
            RequestSessionId = "req-normalize-1",
            LLMRunnerType = "TurboLLM",
            SourceLlm = "monitor",
            DestinationLlm = "expert",
            UserInfo = new UserInfo { AccountType = "Default" }
        };
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

    private sealed class TwoHeadLlmApi : ILLMApi
    {
        public LLMConfig Config { get; } = new();
        public int SystemPromptCount { get; } = 2;

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

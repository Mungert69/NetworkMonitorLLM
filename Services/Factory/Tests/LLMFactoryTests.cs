using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Coordinator;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LLMFactoryTests
{
    private readonly Mock<IHistoryStorage> _historyStorage = new();
    private readonly Mock<ILocalLlmSessionStore> _localLlmSessionStore = new();
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ICpuUsageMonitor> _cpuUsage = new();
    private readonly Mock<IQueryCoordinator> _queryCoordinator = new();
    private readonly LLMFactory _factory;

    public LLMFactoryTests()
    {
        var logger = Mock.Of<ILogger<LLMFactory>>();
        var services = new Mock<IServiceProvider>();
        var systemParams = new SystemParams
        {
            ServiceID = "monitor",
            UserFacingServiceId = "monitor"
        };
        _factory = new LLMFactory(logger, services.Object, _historyStorage.Object, _localLlmSessionStore.Object, _responseProcessor.Object, _cpuUsage.Object, _queryCoordinator.Object, systemParams);
    }

    [Fact]
    public void GetHistoriesForUser_ReturnsMappedDisplayNames()
    {
        var sessions = new ConcurrentDictionary<string, Session>();
        sessions["sess_user1_a"] = new Session
        {
            HistoryDisplayName = new HistoryDisplayName
            {
                SessionId = "abc_ignored",
                Name = "First",
                LlmType = "Turbo",
                UserId = "user1",
                StartUnixTime = 1
            }
        };
        sessions["sess_user2_b"] = new Session
        {
            HistoryDisplayName = new HistoryDisplayName { SessionId = "other", Name = "Other", UserId = "user2" }
        };

        _factory.Sessions = sessions;

        var result = _factory.GetHistoriesForUser("prefix_user1_suffix");

        Assert.Single(result);
        Assert.Equal("abc", result[0].SessionId);
        Assert.Equal("Turbo", result[0].LlmType);
    }

    [Fact]
    public async Task SendHistoryDisplayNames_PushesResponseWhenAvailable()
    {
        var history = new HistoryDisplayName
        {
            SessionId = "sess_user1_a",
            Name = "Display"
        };
        var sessions = new ConcurrentDictionary<string, Session>();
        sessions[history.SessionId] = new Session { HistoryDisplayName = history };
        _factory.Sessions = sessions;

        var processed = new List<string>();
        _responseProcessor
            .Setup(r => r.ProcessLLMOutput(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask)
            .Callback<LLMServiceObj>(obj => processed.Add(obj.LlmMessage));

        var serviceObj = new LLMServiceObj
        {
            SessionId = history.SessionId
        };
        serviceObj.SourceLlm = "TurboLLM";
        serviceObj.DestinationLlm = "TurboLLM";

        await _factory.SendHistoryDisplayNames(serviceObj);

        Assert.Single(processed);
        Assert.Contains("<history-display-name>", processed[0]);
    }

    [Fact]
    public async Task SaveHistoryForSessionAsync_WritesHistoryThroughStorage()
    {
        var historyList = new List<ChatMessage> { ChatMessage.FromUser("hello") };
        var sessionId = "sess_user1_a";
        var session = new Session
        {
            HistoryDisplayName = new HistoryDisplayName { SessionId = sessionId, History = new List<ChatMessage>() }
        };
        var sessions = new ConcurrentDictionary<string, Session>();
        sessions[sessionId] = session;
        _factory.Sessions = sessions;

        var historiesField = typeof(LLMFactory).GetField("_sessionHistories", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var histories = new ConcurrentDictionary<string, List<ChatMessage>>();
        histories[sessionId] = historyList;
        historiesField.SetValue(_factory, histories);

        HistoryDisplayName? saved = null;
        _historyStorage
            .Setup(s => s.SaveHistoryAsync(It.IsAny<HistoryDisplayName>()))
            .Returns(Task.CompletedTask)
            .Callback<HistoryDisplayName>(hdn => saved = hdn);

        await _factory.SaveHistoryForSessionAsync(sessionId);

        Assert.NotNull(saved);
        Assert.Equal(historyList, saved!.History);
    }

    [Fact]
    public async Task SaveHistoryForSessionAsync_TestLlmWritesOnlyToLocalSessionStore()
    {
        var historyList = new List<ChatMessage> { ChatMessage.FromUser("hello") };
        var sessionId = "sess_user1_test";
        var sessions = new ConcurrentDictionary<string, Session>();
        sessions[sessionId] = new Session
        {
            HistoryDisplayName = new HistoryDisplayName { SessionId = sessionId, LlmType = "TestLLM" }
        };
        _factory.Sessions = sessions;

        var historiesField = typeof(LLMFactory).GetField("_sessionHistories", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var histories = new ConcurrentDictionary<string, List<ChatMessage>> { [sessionId] = historyList };
        historiesField.SetValue(_factory, histories);

        _localLlmSessionStore.Setup(s => s.SaveAsync(It.IsAny<HistoryDisplayName>())).Returns(Task.CompletedTask);

        await _factory.SaveHistoryForSessionAsync(sessionId);

        _localLlmSessionStore.Verify(s => s.SaveAsync(It.Is<HistoryDisplayName>(h => h.SessionId == sessionId)), Times.Once);
        _historyStorage.Verify(s => s.SaveHistoryAsync(It.IsAny<HistoryDisplayName>()), Times.Never);
    }

    [Fact]
    public async Task LoadAllSessionsAsync_UsesDataForTestLlmAndRedisForOtherRunners()
    {
        var redisSessions = new ConcurrentDictionary<string, Session>();
        redisSessions["legacy_test"] = new Session
        {
            HistoryDisplayName = new HistoryDisplayName { SessionId = "legacy_test", LlmType = "TestLLM" }
        };
        redisSessions["turbo"] = new Session
        {
            HistoryDisplayName = new HistoryDisplayName { SessionId = "turbo", LlmType = "TurboLLM" }
        };
        var localSessions = new ConcurrentDictionary<string, Session>();
        localSessions["local_test"] = new Session
        {
            HistoryDisplayName = new HistoryDisplayName { SessionId = "local_test", LlmType = "TestLLM" }
        };
        _historyStorage.Setup(s => s.LoadAllSessionsAsync()).ReturnsAsync(redisSessions);
        _localLlmSessionStore.Setup(s => s.LoadAllSessionsAsync()).ReturnsAsync(localSessions);

        var sessions = await _factory.LoadAllSessionsAsync();

        Assert.DoesNotContain("legacy_test", sessions.Keys);
        Assert.Contains("turbo", sessions.Keys);
        Assert.Contains("local_test", sessions.Keys);
    }

    [Fact]
    public async Task SendHistoryDisplayNames_TestLlmUsesOnlyLocalTestLlmSessions()
    {
        var testSession = new HistoryDisplayName
        {
            SessionId = "sess_user1_TestLLM",
            Name = "Local test history",
            LlmType = "TestLLM",
            UserId = "user1"
        };
        var sessions = new ConcurrentDictionary<string, Session>
        {
            [testSession.SessionId] = new Session { HistoryDisplayName = testSession },
            ["sess_user1_TurboLLM"] = new Session
            {
                HistoryDisplayName = new HistoryDisplayName
                {
                    SessionId = "sess_user1_TurboLLM",
                    Name = "Redis history",
                    LlmType = "TurboLLM",
                    UserId = "user1"
                }
            }
        };
        _factory.Sessions = sessions;
        var messages = new List<string>();
        _responseProcessor.Setup(r => r.ProcessLLMOutput(It.IsAny<LLMServiceObj>()))
            .Returns(Task.CompletedTask)
            .Callback<LLMServiceObj>(message => messages.Add(message.LlmMessage));

        await _factory.SendHistoryDisplayNames(new LLMServiceObj
        {
            SessionId = testSession.SessionId,
            LLMRunnerType = "TestLLM",
            HistoryServiceId = "some-other-service",
            SourceLlm = "TestLLM",
            DestinationLlm = "TestLLM"
        });

        var historyPayload = Assert.Single(messages);
        Assert.Contains("Local test history", historyPayload);
        Assert.DoesNotContain("Redis history", historyPayload);
        _historyStorage.Verify(storage => storage.GetHistoryDisplayNamesAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public void OnRunnerLoadChanged_UpdatesLoadAndRunner()
    {
        var runner = new StubRunner("TurboLLM");
        var sessions = new ConcurrentDictionary<string, Session>();
        sessions["sess_user_a"] = new Session { Runner = runner };
        _factory.Sessions = sessions;

        _factory.OnRunnerLoadChanged(1, "TurboLLM");
        _factory.OnRunnerLoadChanged(-5, "TurboLLM");

        Assert.Equal(0, runner.LlmLoad);

        var field = typeof(LLMFactory).GetField("_openAIRunnerFactory", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var factory = (LLMRunnerFactoryBase)field.GetValue(_factory)!;
        Assert.Equal(0, factory.LoadCount);
    }

    [Fact]
    public void SemaphoreConfiguration_UsesExpectedConcurrencyLimits()
    {
        var processSemaphoreField = typeof(LLMFactory).GetField("_processRunnerSemaphore", BindingFlags.NonPublic | BindingFlags.Instance);
        var openAiSemaphoreField = typeof(LLMFactory).GetField("_openAiRunnerSemaphore", BindingFlags.NonPublic | BindingFlags.Instance);
        var hfSemaphoreField = typeof(LLMFactory).GetField("_hfRunnerSemaphore", BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(processSemaphoreField);
        Assert.NotNull(openAiSemaphoreField);
        Assert.NotNull(hfSemaphoreField);

        var processSemaphore = (SemaphoreSlim)processSemaphoreField!.GetValue(_factory)!;
        var openAiSemaphore = (SemaphoreSlim)openAiSemaphoreField!.GetValue(_factory)!;
        var hfSemaphore = (SemaphoreSlim)hfSemaphoreField!.GetValue(_factory)!;

        Assert.Equal(1, processSemaphore.CurrentCount);
        Assert.Equal(8, openAiSemaphore.CurrentCount);
        Assert.Equal(4, hfSemaphore.CurrentCount);
    }

    private sealed class StubRunner : ILLMRunner
    {
        public StubRunner(string type) => Type = type;
        public string Type { get; }
        public bool IsStateReady => true;
        public bool IsStateStarting => false;
        public bool IsStateFailed => false;
        public bool IsEnabled => true;
        public int LlmLoad { get; set; }
        public event Action<int, string>? LoadChanged
        {
            add { }
            remove { }
        }

        public event Func<string, LLMServiceObj, Task>? OnUserMessage
        {
            add { }
            remove { }
        }

        public event Func<LLMServiceObj, Task>? SendHistory
        {
            add { }
            remove { }
        }

        public event Func<string, LLMServiceObj, Task>? RemoveSavedSession
        {
            add { }
            remove { }
        }

        public Task RemoveProcess(string sessionId) => Task.CompletedTask;
        public Task SendInputAndGetResponse(LLMServiceObj serviceObj) => Task.CompletedTask;
        public Task StartProcess(LLMServiceObj serviceObj) => Task.CompletedTask;
        public Task StopRequest(string sessionId) => Task.CompletedTask;
    }
}

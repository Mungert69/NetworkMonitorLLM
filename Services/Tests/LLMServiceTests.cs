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
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LLMServiceTests
{
    [Fact]
    public async Task StartProcess_CreatesRunnerAndPublishesMessages()
    {
        var rabbit = new Mock<IRabbitRepo>();
        rabbit.Setup(r => r.PublishAsync<LLMServiceObj>(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), It.IsAny<string>()))
              .Returns(Task.CompletedTask);
        rabbit.Setup(r => r.PublishAsync(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<string>()))
              .Returns(Task.CompletedTask);

        var factory = new Mock<ILLMFactory>();
        var sessionsFromFactory = new ConcurrentDictionary<string, Session>();
        factory.Setup(f => f.LoadAllSessionsAsync()).ReturnsAsync(sessionsFromFactory);
        factory.SetupSet(f => f.Sessions = It.IsAny<ConcurrentDictionary<string, Session>>());

        var runner = new StubRunner { Type = "TurboLLM" };
        factory.Setup(f => f.CreateRunner("TurboLLM", It.IsAny<LLMServiceObj>()))
               .ReturnsAsync(runner);

        var service = CreateService(rabbit.Object, factory.Object, serviceId: "custom");
        await service.Init();

        var request = new LLMServiceObj
        {
            RequestSessionId = "sess",
            LLMRunnerType = "TurboLLM",
            UserInfo = new UserInfo { UserID = "user1" }
        };

        await service.StartProcess(request);

        Assert.True(runner.StartProcessCalled);
        Assert.Equal("sess_TurboLLM", request.SessionId);

        var sessions = GetSessions(service);
        Assert.True(sessions.ContainsKey("sess_TurboLLM"));

        rabbit.Verify(r => r.PublishAsync<LLMServiceObj>("llmServiceMessage", It.IsAny<LLMServiceObj>(), It.IsAny<string>()), Times.Once);
        rabbit.Verify(r => r.PublishAsync<LLMServiceObj>("llmServiceStarted", request, It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task StopRequest_ReturnsErrorWhenSessionMissing()
    {
        var (service, rabbit, _, _) = CreateConfiguredService();
        await service.Init();

        var result = await service.StopRequest(new LLMServiceObj { SessionId = "missing" });

        Assert.False(result.Success);
        Assert.Contains("Could not find session", result.Message);
        rabbit.Verify(r => r.PublishAsync<LLMServiceObj>("llmServiceMessage", It.IsAny<LLMServiceObj>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task StopRequest_WhenRunnerPresent_HaltsOutput()
    {
        var (service, rabbit, _, _) = CreateConfiguredService();
        await service.Init();

        var runner = new StubRunner { Type = "TurboLLM" };
        var sessions = GetSessions(service);
        sessions["sess_TurboLLM"] = new Session
        {
            FullSessionId = "sess_TurboLLM",
            Runner = runner,
            HistoryDisplayName = new HistoryDisplayName { LlmType = "TurboLLM" }
        };

        var obj = new LLMServiceObj { SessionId = "sess_TurboLLM" };
        var result = await service.StopRequest(obj);

        Assert.True(result.Success);
        Assert.True(runner.StopRequested);
        rabbit.Verify(r => r.PublishAsync<LLMServiceObj>("llmServiceMessage", It.IsAny<LLMServiceObj>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task SendInputAndGetResponse_WhenRunnerStarting_ReturnsWaitMessage()
    {
        var (service, rabbit, _, _) = CreateConfiguredService();
        await service.Init();

        var runner = new StubRunner { StateStarting = true, StateReady = false };
        var sessions = GetSessions(service);
        sessions["sess_TurboLLM"] = new Session
        {
            FullSessionId = "sess_TurboLLM",
            Runner = runner
        };

        var obj = new LLMServiceObj { SessionId = "sess_TurboLLM" };
        var result = await service.SendInputAndGetResponse(obj);

        Assert.False(result.Success);
        Assert.Contains("starting", result.Message, StringComparison.OrdinalIgnoreCase);
        rabbit.Verify(r => r.PublishAsync<LLMServiceObj>("llmServiceMessage", It.IsAny<LLMServiceObj>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task RemoveAllSessionIdProcesses_SavesHistoryAndStopsRunners()
    {
        var (service, rabbit, factory, _) = CreateConfiguredService();
        factory.Setup(f => f.SaveHistoryForSessionAsync(It.IsAny<string>())).Returns(Task.CompletedTask);
        await service.Init();

        var sessions = GetSessions(service);
        var runner1 = new StubRunner { Type = "TurboLLM" };
        var runner2 = new StubRunner { Type = "HugLLM" };
        sessions["base_TurboLLM"] = new Session { FullSessionId = "base_TurboLLM", Runner = runner1, HistoryDisplayName = new HistoryDisplayName { LlmType = "TurboLLM" } };
        sessions["base_HugLLM"] = new Session { FullSessionId = "base_HugLLM", Runner = runner2, HistoryDisplayName = new HistoryDisplayName { LlmType = "HugLLM" } };

        var obj = new LLMServiceObj { SessionId = "base_TurboLLM" };
        var result = await service.RemoveAllSessionIdProcesses(obj);

        Assert.True(result.Success);
        factory.Verify(f => f.SaveHistoryForSessionAsync("base_TurboLLM"), Times.Once);
        factory.Verify(f => f.SaveHistoryForSessionAsync("base_HugLLM"), Times.Once);
        Assert.True(runner1.RemoveCalled);
        Assert.True(runner2.RemoveCalled);
        Assert.Null(sessions["base_TurboLLM"].Runner);
        Assert.Null(sessions["base_HugLLM"].Runner);
        rabbit.Verify(r => r.PublishAsync<LLMServiceObj>("llmSessionMessage", It.IsAny<LLMServiceObj>(), It.IsAny<string>()), Times.Once);
    }

    private static (LLMService service, Mock<IRabbitRepo> rabbit, Mock<ILLMFactory> factory, ConcurrentDictionary<string, Session> initialSessions) CreateConfiguredService(string serviceId = "custom")
    {
        var rabbit = new Mock<IRabbitRepo>();
        rabbit.Setup(r => r.PublishAsync<LLMServiceObj>(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), It.IsAny<string>()))
              .Returns(Task.CompletedTask);
        rabbit.Setup(r => r.PublishAsync(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<string>()))
              .Returns(Task.CompletedTask);

        var factory = new Mock<ILLMFactory>();
        var sessions = new ConcurrentDictionary<string, Session>();
        factory.Setup(f => f.LoadAllSessionsAsync()).ReturnsAsync(sessions);
        factory.SetupSet(f => f.Sessions = It.IsAny<ConcurrentDictionary<string, Session>>());

        var service = CreateService(rabbit.Object, factory.Object, serviceId);
        return (service, rabbit, factory, sessions);
    }

    private static LLMService CreateService(IRabbitRepo rabbitRepo, ILLMFactory factory, string serviceId)
    {
        var logger = Mock.Of<ILogger<LLMService>>();
        var systemParams = new SystemParams { ServiceID = serviceId };
        var mlParams = new MLParams();
        var provider = new Mock<IServiceProvider>();
        provider.Setup(p => p.GetService(It.IsAny<Type>())).Returns((object?)null);

        return new LLMService(logger, rabbitRepo, systemParams, mlParams, provider.Object, factory);
    }

    private static ConcurrentDictionary<string, Session> GetSessions(LLMService service)
    {
        var field = typeof(LLMService).GetField("_sessions", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (ConcurrentDictionary<string, Session>)field.GetValue(service)!;
    }

    private sealed class StubRunner : ILLMRunner
    {
        public string Type { get; set; } = "TurboLLM";
        public bool StateReady { get; set; } = true;
        public bool StateStarting { get; set; } = false;
        public bool StateFailed { get; set; } = false;
        public bool Enabled { get; set; } = true;
        public bool StartProcessCalled { get; private set; }
        public bool StopRequested { get; private set; }
        public bool RemoveCalled { get; private set; }
        public LLMServiceObj? LastSendInput { get; private set; }
        public int LlmLoad { get; set; }

        public bool IsStateReady => StateReady;
        public bool IsStateStarting => StateStarting;
        public bool IsStateFailed => StateFailed;
        public bool IsEnabled => Enabled;

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

        public Task StartProcess(LLMServiceObj serviceObj)
        {
            StartProcessCalled = true;
            return Task.CompletedTask;
        }

        public Task SendInputAndGetResponse(LLMServiceObj serviceObj)
        {
            LastSendInput = serviceObj;
            return Task.CompletedTask;
        }

        public Task RemoveProcess(string sessionId)
        {
            RemoveCalled = true;
            return Task.CompletedTask;
        }

        public Task StopRequest(string sessionId)
        {
            StopRequested = true;
            return Task.CompletedTask;
        }
    }
}

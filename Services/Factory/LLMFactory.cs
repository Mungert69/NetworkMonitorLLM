using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Coordinator;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Betalgo.Ranul.OpenAI.Managers;
using System.Collections.Generic;
using System.Collections.Concurrent;

using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;


namespace NetworkMonitor.LLM.Services;


public interface ILLMFactory
{
    Task<ILLMRunner> CreateRunner(string runnerType, LLMServiceObj obj);
    void OnRunnerLoadChanged(int delta, string llmType);
    ConcurrentDictionary<string, Session> Sessions { set; }
    Task DeleteHistoryForSessionAsync(string sessionId, LLMServiceObj serviceObj);
    Task SaveHistoryForSessionAsync(string sessionId);
    Task SendHistoryDisplayNames(LLMServiceObj serviceObj);
    Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync();
}

public interface ILocalLlmContextProvider
{
    string LocalLlmContext { get; }
}

public class LLMFactory : ILLMFactory
{

    private readonly ILLMRunnerFactory _processRunnerFactory;
    private readonly ILLMRunnerFactory _openAIRunnerFactory;
    private readonly ILLMRunnerFactory _hfRunnerFactory;
    private readonly IHistoryStorage _historyStorage;
    private readonly ILocalLlmSessionStore _localLlmSessionStore;
    private readonly ILogger _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly SemaphoreSlim _processRunnerSemaphore = new SemaphoreSlim(1, 1);
    private readonly SemaphoreSlim _openAiRunnerSemaphore = new SemaphoreSlim(8, 8);
    private readonly SemaphoreSlim _hfRunnerSemaphore = new SemaphoreSlim(4, 4);
    private readonly ILLMResponseProcessor _responseProcessor;
    private ConcurrentDictionary<string, Session> _sessions = new();
    public ConcurrentDictionary<string, Session> Sessions { set => _sessions = value; }
    private readonly ICpuUsageMonitor _cpuUsageMonitor;
    private readonly IQueryCoordinator _queryCoordinator;
    private readonly string _serviceId;
    private readonly string _userFacingServiceId;


    private readonly ConcurrentDictionary<string, List<ChatMessage>> _sessionHistories = new();

    public LLMFactory(ILogger<LLMFactory> logger, IServiceProvider serviceProvider, IHistoryStorage historyStorage, ILocalLlmSessionStore localLlmSessionStore, ILLMResponseProcessor responseProcessor, ICpuUsageMonitor cpuUsageMonitor, IQueryCoordinator queryCoordinator, SystemParams systemParams)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _historyStorage = historyStorage;
        _localLlmSessionStore = localLlmSessionStore;
        _cpuUsageMonitor = cpuUsageMonitor;
        _processRunnerFactory = new LLMProcessRunnerFactory();
        _openAIRunnerFactory = new OpenAIRunnerFactory();
        _hfRunnerFactory = new HFRunnerFactory();
        _responseProcessor = responseProcessor;
        _queryCoordinator = queryCoordinator;
        _serviceId = systemParams.ServiceID ?? "Service";
        _userFacingServiceId = string.IsNullOrWhiteSpace(systemParams.UserFacingServiceId)
            ? "monitor"
            : systemParams.UserFacingServiceId;

    }

    public async Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
    {
        var redisSessions = await _historyStorage.LoadAllSessionsAsync();
        // TestLLM sessions are owned by the persistent /data store. Do not revive
        // a legacy Redis copy during startup, otherwise Redis and /data can diverge.
        var sessions = new ConcurrentDictionary<string, Session>(
            redisSessions.Where(session => !IsLocalTestLlmSession(session.Value)));
        var localSessions = await _localLlmSessionStore.LoadAllSessionsAsync();
        foreach (var localSession in localSessions)
        {
            sessions[localSession.Key] = localSession.Value;
        }
        return sessions;
    }
    public List<HistoryDisplayName> GetHistoriesForUser(string sessionId)
    {
        var historyDisplayNames = new List<HistoryDisplayName>();
        string userId = "";
        try
        {

            var sessionIdParts = sessionId.Split('_'); // Split the key on '-'

            if (sessionIdParts.Length >= 3) // Ensure we have enough parts to extract data
            {
                userId = sessionIdParts[1];
            }
            if (userId == "")
            {
                return historyDisplayNames;
            }
            historyDisplayNames = _sessions
            .Where(kvp => kvp.Key.Contains($"_{userId}_"))
            .Select(kvp => kvp.Value.HistoryDisplayName) // Get HistoryDisplayName
            .Where(hdn => hdn != null) // Ensure it's not null
            .Select(hdn => new HistoryDisplayName
            {
                SessionId = hdn.SessionId.Split('_')[0],
                Name = hdn.Name,
                StartUnixTime = hdn.StartUnixTime,
                LlmType = hdn.LlmType,
                UserId = hdn.UserId
            })
            .ToList();

        }
        catch (Exception e)
        {
            _logger.LogError($" Error : can not get histories for userId {userId} . Error was {e.Message}");
        }

        return historyDisplayNames;
    }

    public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesForUserAsync(string userId)
    {
        return await _historyStorage.GetHistoryDisplayNamesAsync(userId, _userFacingServiceId);
    }


    public async Task SendHistoryDisplayNames(LLMServiceObj serviceObj)
    {
        if (!string.Equals(_serviceId, _userFacingServiceId, StringComparison.OrdinalIgnoreCase)) return;
        if (!serviceObj.IsPrimaryLlm) return;
        try
        {
            var isLocalTestLlm = string.Equals(serviceObj.LLMRunnerType, "TestLLM", StringComparison.OrdinalIgnoreCase)
                || (_sessions.TryGetValue(serviceObj.SessionId, out var currentSession)
                    && IsLocalTestLlmSession(currentSession));
            var historyServiceId = string.IsNullOrWhiteSpace(serviceObj.HistoryServiceId)
                ? _userFacingServiceId
                : serviceObj.HistoryServiceId;
            var historyDisplayNames = GetHistoriesForUser(serviceObj.SessionId);
            if (isLocalTestLlm)
            {
                // TestLLM recovery state is local to this Space. Do not let a
                // stale cross-service selection replace its /data history list
                // with Redis histories from an API-backed runner.
                historyDisplayNames = historyDisplayNames
                    .Where(history => string.Equals(history.LlmType, "TestLLM", StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }
            else if (!string.Equals(historyServiceId, _serviceId, StringComparison.OrdinalIgnoreCase))
            {
                var userId = ExtractUserIdFromSessionId(serviceObj.SessionId);
                if (!string.IsNullOrWhiteSpace(userId))
                {
                    var storedHistories = await _historyStorage.GetHistoryDisplayNamesAsync(userId, historyServiceId);
                    historyDisplayNames = storedHistories.Select(hdn => new HistoryDisplayName
                    {
                        SessionId = hdn.SessionId.Split('_')[0],
                        Name = hdn.Name,
                        StartUnixTime = hdn.StartUnixTime,
                        LlmType = hdn.LlmType,
                        UserId = hdn.UserId
                    }).ToList();
                }
                else
                {
                    historyDisplayNames = new List<HistoryDisplayName>();
                }
            }
            if (historyDisplayNames != null && historyDisplayNames.Count > 0)
            {
                var payload = JsonConvert.SerializeObject(historyDisplayNames, new JsonSerializerSettings
                {
                    ContractResolver = new CamelCasePropertyNamesContractResolver(),
                    Formatting = Formatting.Indented
                });
                var responseServiceObj = new LLMServiceObj(serviceObj);
                responseServiceObj.LlmMessage = $"<history-display-name>{payload}</history-display-name>";
                await _responseProcessor.ProcessLLMOutput(responseServiceObj);
            }
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : failed to send History Display Names. Error was : {e.Message}");
        }


    }

    private static string ExtractUserIdFromSessionId(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return "";
        var parts = sessionId.Split('_');
        return parts.Length >= 3 ? parts[1] : "";
    }

    private async Task SaveAndSendForSessionAsync(LLMServiceObj serviceObj, bool send)
    {

        await SaveHistoryForSessionAsync(serviceObj.SessionId);
        if (send) await SendHistoryDisplayNames(serviceObj);

    }

    public async Task SaveHistoryForSessionAsync(string sessionId)
    {
        try
        {
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                // Update the History property of the HistoryDisplayName object
                session.HistoryDisplayName!.History = _sessionHistories[sessionId];

                if (IsLocalTestLlmSession(session))
                {
                    await _localLlmSessionStore.SaveAsync(session.HistoryDisplayName);
                }
                else
                {
                    await _historyStorage.SaveHistoryAsync(session.HistoryDisplayName);
                }
            }
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : Ca not save sesssion for sessionId {sessionId}. Error was : {e.Message}");
        }

    }

    public async Task DeleteHistoryForSessionAsync(string fullSessionId, LLMServiceObj serviceObj)
    {
        try
        {
            if (_sessions.TryGetValue(fullSessionId, out var session) && IsLocalTestLlmSession(session))
            {
                await _localLlmSessionStore.DeleteAsync(fullSessionId);
            }
            else
            {
                await _historyStorage.DeleteHistoryAsync(fullSessionId);
            }
            _sessions.TryRemove(fullSessionId, out _);
            _sessionHistories.TryRemove(fullSessionId, out _);
            await SendHistoryDisplayNames(serviceObj);
            _sessionHistories.TryRemove(fullSessionId, out _);
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : can not delete history for fullSesionId {fullSessionId}. Error was : {e.Message}");
        }

    }
    public async Task SendHistoryAsync(LLMServiceObj serviceObj)
    {
        try
        {
            await SendHistoryDisplayNames(serviceObj);
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : send History Async . Error was : {e.Message}");
        }
    }

    public async Task OnUserMessageAsync(string message, LLMServiceObj serviceObj)
    {
        try
        {
            bool send = false;
            string sessionId = serviceObj.SessionId;
            if (!serviceObj.IsPrimaryLlm) return;

            // Check if the session exists in _sessions
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                var historyDisplayName = session.HistoryDisplayName!;
                if (session.Runner is ILocalLlmContextProvider localLlmContextProvider)
                {
                    historyDisplayName.LocalLlmContext = localLlmContextProvider.LocalLlmContext;
                }
                // Update the History property with the chat history from _sessionHistories
                if (_sessionHistories.TryGetValue(sessionId, out var history))
                {
                    historyDisplayName.History = history;
                }

                // Update the Name property if it is empty
                if (string.IsNullOrEmpty(historyDisplayName.Name))
                {
                    historyDisplayName.Name = message;
                    send = true;
                }

                await SaveAndSendForSessionAsync(serviceObj, send);
            }
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : unable to run On user Message . Error was : {e.Message}");
        }

    }

    public async Task<ILLMRunner> CreateRunner(string runnerType, LLMServiceObj serviceObj)
    {
        var history = new List<ChatMessage>();
        string localLlmContext = string.Empty;
        try
        {
            history = _sessionHistories.GetOrAdd(serviceObj.SessionId, _ => new List<ChatMessage>());
            if (_sessions.TryGetValue(serviceObj.SessionId, out var existingSession))
            {
                localLlmContext = existingSession.HistoryDisplayName?.LocalLlmContext ?? string.Empty;
            }
            var historyDisplayNames = new List<HistoryDisplayName>();
            // If the history is empty, load it from the runner's own durable store.
            if (history.Count == 0)
            {
                var historyDisplayName = string.Equals(runnerType, "TestLLM", StringComparison.Ordinal)
                    ? await _localLlmSessionStore.LoadAsync(serviceObj.SessionId)
                    : await _historyStorage.LoadHistoryAsync(serviceObj.SessionId);
                if (historyDisplayName != null)
                {
                    history.AddRange(historyDisplayName.History);
                    localLlmContext = historyDisplayName.LocalLlmContext;
                }

            }
            //await SendHistoryDisplayNames(serviceObj);
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : while setting up history and sending history display names in CreateRunner. Error was : {e.Message}");
        }

        ILLMRunner runner = runnerType switch
        {
            "TurboLLM" => _openAIRunnerFactory.CreateRunner(_serviceProvider, serviceObj, _openAiRunnerSemaphore, history, _cpuUsageMonitor),
            "HugLLM" => _hfRunnerFactory.CreateRunner(_serviceProvider, serviceObj, _hfRunnerSemaphore, history, _cpuUsageMonitor),
            "TestLLM" => _processRunnerFactory.CreateRunner(_serviceProvider, serviceObj, _processRunnerSemaphore, history, _cpuUsageMonitor),
            _ => throw new ArgumentException($"Invalid runner type: {runnerType}")
        };

        if (runner is LLMProcessRunner localRunner)
        {
            localRunner.SetLocalLlmContext(localLlmContext);
        }

        runner.LoadChanged += OnRunnerLoadChanged;
        runner.OnUserMessage += async (sessionId, serviceObj) =>
     {
         await OnUserMessageAsync(sessionId, serviceObj);
     };
        runner.RemoveSavedSession += async (sessionId, serviceObj) =>
     {
         await DeleteHistoryForSessionAsync(sessionId, serviceObj);
     };
        runner.SendHistory += async (serviceObj) =>
       {
           await SendHistoryAsync(serviceObj);
       };

        return runner;
    }

    private static bool IsLocalTestLlmSession(Session session)
    {
        return string.Equals(session.HistoryDisplayName?.LlmType, "TestLLM", StringComparison.OrdinalIgnoreCase);
    }

    public void OnRunnerLoadChanged(int delta, string llmType)
    {
        // Update the load count for the respective runner type
        if (llmType == "TurboLLM")
        {
            _openAIRunnerFactory.LoadCount += delta;
        }
        else if (llmType == "HugLLM")
        {
            _hfRunnerFactory.LoadCount += delta;
        }
        else if (llmType == "TestLLM")
        {
            _processRunnerFactory.LoadCount += delta;
        }
        else
        {
            _logger.LogWarning($"Unknown LLM type: {llmType}. Load update ignored.");
            return;
        }

        // Broadcast the updated load counts to the relevant sessions
        foreach (var session in _sessions.Values)
        {
            if (session.Runner != null)
            {
                if (session.Runner.Type == llmType)
                {
                    // Update the session's runner with the specific load for its type
                    session.Runner.LlmLoad = llmType switch
                    {
                        "TurboLLM" => _openAIRunnerFactory.LoadCount,
                        "TestLLM" => _processRunnerFactory.LoadCount,
                        "HugLLM" => _hfRunnerFactory.LoadCount,
                        _ => 0 // Fallback case (shouldn't occur due to earlier check)
                    };
                }
                // Optionally log the updated load counts
                //_logger.LogInformation($"Sent Load Update to {llmType} LLM : {session.Runner.LlmLoad} ");

            }
        }

    }

}

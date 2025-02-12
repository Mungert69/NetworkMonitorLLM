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
public class LLMFactory : ILLMFactory
{

    private readonly ILLMRunnerFactory _processRunnerFactory;
    private readonly ILLMRunnerFactory _openAIRunnerFactory;
    private readonly ILLMRunnerFactory _hfRunnerFactory;
    private readonly IHistoryStorage _historyStorage;
    private readonly ILogger _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly SemaphoreSlim _processRunnerSemaphore = new SemaphoreSlim(1, 1);
    private readonly ILLMResponseProcessor _responseProcessor;
    private ConcurrentDictionary<string, Session> _sessions;
    public ConcurrentDictionary<string, Session> Sessions { set => _sessions = value; }
    private readonly ICpuUsageMonitor _cpuUsageMonitor;


    private readonly ConcurrentDictionary<string, List<ChatMessage>> _sessionHistories = new();

    public LLMFactory(ILogger<LLMFactory> logger, IServiceProvider serviceProvider, IHistoryStorage historyStorage, ILLMResponseProcessor responseProcessor,  ICpuUsageMonitor cpuUsageMonitor)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _historyStorage = historyStorage;
        _cpuUsageMonitor=cpuUsageMonitor;
        _processRunnerFactory = new LLMProcessRunnerFactory();
        _openAIRunnerFactory = new OpenAIRunnerFactory();
        _hfRunnerFactory = new HFRunnerFactory();
        _responseProcessor = responseProcessor;

    }

    public Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
    {
        return _historyStorage.LoadAllSessionsAsync();
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
        return await _historyStorage.GetHistoryDisplayNamesAsync(userId);
    }

 
    public async Task SendHistoryDisplayNames(LLMServiceObj serviceObj)
    {
        if (!serviceObj.IsPrimaryLlm) return;
        try
        {
            var historyDisplayNames = GetHistoriesForUser(serviceObj.SessionId);
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

                // Save the updated HistoryDisplayName object
                await _historyStorage.SaveHistoryAsync(session.HistoryDisplayName);
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
            await _historyStorage.DeleteHistoryAsync(fullSessionId);
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
            await SendHistoryDisplayNames( serviceObj);
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
        try
        {
            history = _sessionHistories.GetOrAdd(serviceObj.SessionId, _ => new List<ChatMessage>());
            var historyDisplayNames = new List<HistoryDisplayName>();
            // If the history is empty, attempt to load it from storage asynchronously
            if (history.Count == 0)
            {
                var historyDisplayName = await _historyStorage.LoadHistoryAsync(serviceObj.SessionId);
                history.AddRange(historyDisplayName.History);
                
            }
            //await SendHistoryDisplayNames(serviceObj);
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : while setting up history and sending history display names in CreateRunner. Error was : {e.Message}");
        }

        ILLMRunner runner = runnerType switch
        {
            "TurboLLM" => _openAIRunnerFactory.CreateRunner(_serviceProvider, serviceObj, new SemaphoreSlim(1), history,_cpuUsageMonitor),
            "HugLLM" => _hfRunnerFactory.CreateRunner(_serviceProvider, serviceObj, new SemaphoreSlim(1), history,_cpuUsageMonitor),
            "FreeLLM" => _processRunnerFactory.CreateRunner(_serviceProvider, serviceObj, _processRunnerSemaphore, history, _cpuUsageMonitor),
            _ => throw new ArgumentException($"Invalid runner type: {runnerType}")
        };

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
         await SendHistoryAsync( serviceObj);
     };

        return runner;
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
            _openAIRunnerFactory.LoadCount += delta;
        }
        else if (llmType == "FreeLLM")
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
                        "FreeLLM" => _processRunnerFactory.LoadCount,
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
// LLMProcessRunner.cs
public interface ILLMRunner
{
    Task StartProcess(LLMServiceObj serviceObj);
    Task SendInputAndGetResponse(LLMServiceObj serviceObj);
    Task RemoveProcess(string sessionId);
    Task StopRequest(string sessionId);

    string Type { get; }
    bool IsStateReady { get; }
    bool IsStateStarting { get; }
    bool IsStateFailed { get; }
    bool IsEnabled { get; }
    int LlmLoad { get; set; }
    event Action<int, string> LoadChanged;
    event Func<string, LLMServiceObj, Task> OnUserMessage;
    event Func<LLMServiceObj, Task> SendHistory;
    event Func<string, LLMServiceObj, Task> RemoveSavedSession;

}

public abstract class LLMRunnerFactoryBase : ILLMRunnerFactory
{
    private int _loadCount;

    public int LoadCount
    {
        get => _loadCount;
        set
        {
            _loadCount = value < 0 ? 0 : value;
        }
    }

    public abstract ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor);

}


public interface ILLMRunnerFactory
{
    int LoadCount { get; set; }
    ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor);

}


public class LLMProcessRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor)
    {
        return new LLMProcessRunner(serviceProvider.GetRequiredService<ILogger<LLMProcessRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, runnerSemaphore, serviceProvider.GetRequiredService<IAudioGenerator>(), cpuUsageMonitor);
    }
}

public class OpenAIRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<OpenAIService>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, runnerSemaphore, serviceProvider.GetRequiredService<IAudioGenerator>(), false, history);
    }
}

public class HFRunnerFactory : LLMRunnerFactoryBase
{


    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<OpenAIService>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, runnerSemaphore, serviceProvider.GetRequiredService<IAudioGenerator>(), true, history);
    }
}
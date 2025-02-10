using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
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
    Task DeleteHistoryForSessionAsync(string sessionId);
    Task SaveHistoryForSessionAsync(string sessionId);
    Task LoadHistoryForSessionAsync(string sessionId);
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
    private ConcurrentDictionary<string, Session> _sessions;
    public ConcurrentDictionary<string, Session> Sessions { set => _sessions = value; }


    private readonly ConcurrentDictionary<string, List<ChatMessage>> _sessionHistories = new();

    public LLMFactory(ILogger<LLMFactory> logger, IServiceProvider serviceProvider, IHistoryStorage historyStorage)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _historyStorage = historyStorage;
        _processRunnerFactory = new LLMProcessRunnerFactory();
        _openAIRunnerFactory = new OpenAIRunnerFactory();
        _hfRunnerFactory = new HFRunnerFactory();
    }


    public List<HistoryDisplayName> GetHistoriesForUser(string sessionId)
    {
        var historyDisplayNames = new List<HistoryDisplayName>();

        try
        {
            string userId = "";
            var sessionIdParts = sessionId.Split('_'); // Split the key on '-'

            if (sessionIdParts.Length >= 3) // Ensure we have enough parts to extract data
            {
                userId = sessionIdParts[1]; // Map the SessionId
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
                SessionId = hdn.SessionId, // Copy properties
                Name = hdn.Name,
                StartUnixTime = hdn.StartUnixTime
            })
            .ToList();

        }
        catch { }

        return historyDisplayNames;
    }

    public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesForUserAsync(string userId)
    {
        return await _historyStorage.GetHistoryDisplayNamesAsync(userId);
    }

    public async Task LoadHistoryForSessionAsync(string sessionId)
    {
        if (!_sessions.ContainsKey(sessionId))
        {
            // Load the HistoryDisplayName object from storage
            var historyDisplayName = await _historyStorage.LoadHistoryAsync(sessionId);

            // If no history exists, create a new HistoryDisplayName object with an empty History
            if (historyDisplayName == null)
            {
                _logger.LogWarning($" Warning : no historyDisplayName object found for sessionsId {sessionId}");
                return;
            }

            // Update or create the entry in _sessionHistories
            _sessionHistories[sessionId] = historyDisplayName.History;

            // Store the HistoryDisplayName object in _sessions
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                session.HistoryDisplayName = historyDisplayName;
            }
            _logger.LogInformation($" Success : loaded history for sessionId {sessionId}  Name {historyDisplayName.Name} History Count {historyDisplayName.History.Count} ");


        }
    }


    public async Task SaveHistoryForSessionAsync(string sessionId)
    {

        if (_sessions.TryGetValue(sessionId, out var session))
        {
             // Update the History property of the HistoryDisplayName object
            session.HistoryDisplayName!.History = _sessionHistories[sessionId];

            // Save the updated HistoryDisplayName object
            await _historyStorage.SaveHistoryAsync(session.HistoryDisplayName);
        }
    }

    public async Task DeleteHistoryForSessionAsync(string sessionId)
    {
        if (_sessionHistories.TryRemove(sessionId, out _))
        {
            await _historyStorage.DeleteHistoryAsync(sessionId);
        }
    }

    public void OnUserMessage(string message, string sessionId)
    {
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
            }
            // it may be bad for performance to do this
            _ = SaveHistoryForSessionAsync(sessionId);
        }
    }

    public async Task<ILLMRunner> CreateRunner(string runnerType, LLMServiceObj obj)
    {

        var history = _sessionHistories.GetOrAdd(obj.SessionId, _ => new List<ChatMessage>());
        var historyDisplayNames = new List<HistoryDisplayName>();
        // If the history is empty, attempt to load it from storage asynchronously
        if (history.Count == 0)
        {
            // Asynchronously load the history
            await LoadHistoryForSessionAsync(obj.SessionId);

            // After loading, ensure the session history is updated
            if (_sessionHistories.TryGetValue(obj.SessionId, out var loadedHistory))
            {
                history.AddRange(loadedHistory);
            }
        }

        if (obj.IsPrimaryLlm) historyDisplayNames = GetHistoriesForUser(obj.SessionId);
        ILLMRunner runner = runnerType switch
        {
            "TurboLLM" => _openAIRunnerFactory.CreateRunner(_serviceProvider, obj, new SemaphoreSlim(1), history, historyDisplayNames),
            "HugLLM" => _hfRunnerFactory.CreateRunner(_serviceProvider, obj, new SemaphoreSlim(1), history, historyDisplayNames),
            //"FreeLLM" => _processRunnerFactory.CreateRunner(_serviceProvider, obj, _processRunnerSemaphore, history, historyDisplayNames),
            _ => throw new ArgumentException($"Invalid runner type: {runnerType}")
        };

        runner.LoadChanged += OnRunnerLoadChanged;
        runner.OnUserMessage += OnUserMessage;

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
    event Action<string, string> OnUserMessage;

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

    public abstract ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, List<HistoryDisplayName> historyDisplaysNames);

}


public interface ILLMRunnerFactory
{
    int LoadCount { get; set; }
    ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, List<HistoryDisplayName> historyDisplaysNames);

}


public class LLMProcessRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, List<HistoryDisplayName> historyDisplaysNames)
    {
        return new LLMProcessRunner(serviceProvider.GetRequiredService<ILogger<LLMProcessRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, runnerSemaphore, serviceProvider.GetRequiredService<IAudioGenerator>());
    }
}

public class OpenAIRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, List<HistoryDisplayName> historyDisplaysNames)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<OpenAIService>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, runnerSemaphore, serviceProvider.GetRequiredService<IAudioGenerator>(), false, history, historyDisplaysNames);
    }
}

public class HFRunnerFactory : LLMRunnerFactoryBase
{


    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim runnerSemaphore, List<ChatMessage> history, List<HistoryDisplayName> historyDisplaysNames)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<OpenAIService>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, runnerSemaphore, serviceProvider.GetRequiredService<IAudioGenerator>(), true, history, historyDisplaysNames);
    }
}
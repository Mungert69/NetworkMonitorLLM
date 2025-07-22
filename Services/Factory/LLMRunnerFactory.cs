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

    public abstract ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor);

}


public interface ILLMRunnerFactory
{
    int LoadCount { get; set; }
    ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor);

}


public class LLMProcessRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor)
    {
        return new LLMProcessRunner(serviceProvider.GetRequiredService<ILogger<LLMProcessRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<SystemParams>(), serviceProvider.GetRequiredService<MLParams>(), serviceObj, runnerSemaphore, serviceProvider.GetRequiredService<IAudioGenerator>(), cpuUsageMonitor, serviceProvider.GetRequiredService<IQueryCoordinator>());
    }
}

public class OpenAIRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<OpenAIService>(), serviceProvider.GetRequiredService<SystemParams>(), serviceProvider.GetRequiredService<MLParams>(), serviceObj, null, serviceProvider.GetRequiredService<IAudioGenerator>(), false, history, serviceProvider.GetRequiredService<IQueryCoordinator>(), serviceProvider.GetRequiredService<IToolsBuilderFactory>());
    }
}

public class HFRunnerFactory : LLMRunnerFactoryBase
{


    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<OpenAIService>(), serviceProvider.GetRequiredService<SystemParams>(), serviceProvider.GetRequiredService<MLParams>(), serviceObj, null, serviceProvider.GetRequiredService<IAudioGenerator>(), true, history, serviceProvider.GetRequiredService<IQueryCoordinator>(), serviceProvider.GetRequiredService<IToolsBuilderFactory>());
    }
}
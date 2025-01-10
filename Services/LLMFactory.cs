using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Betalgo.Ranul.OpenAI.Managers;


namespace NetworkMonitor.LLM.Services;
// LLMProcessRunner.cs
public interface ILLMRunner
{
    Task StartProcess(LLMServiceObj serviceObj, DateTime currentTime);
    Task SendInputAndGetResponse(LLMServiceObj serviceObj);
    Task RemoveProcess(string sessionId);
    Task StopRequest(string sessionId);

    string Type { get; }
    bool IsStateReady { get; }
    bool IsStateStarting { get; }
    bool IsStateFailed { get; }
    bool IsEnabled { get; }
    int LlmLoad {get;set;}
    event Action<int,string> LoadChanged;

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
    public abstract ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? runnerSemaphore);
}


public interface ILLMRunnerFactory
{
     public int LoadCount{get;set;}
    ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? _runnerSemaphore = null);
}


public class LLMProcessRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? _runnerSemaphore)
    {
        return new LLMProcessRunner(serviceProvider.GetRequiredService<ILogger<LLMProcessRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, _runnerSemaphore!);
    }
}

public class OpenAIRunnerFactory : LLMRunnerFactoryBase
{

    public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? _runnerSemaphore)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(), serviceProvider.GetRequiredService<ILLMResponseProcessor>(), serviceProvider.GetRequiredService<OpenAIService>(), serviceProvider.GetRequiredService<ISystemParamsHelper>(), serviceObj, _runnerSemaphore!);
    }
}
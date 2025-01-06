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
     void StopRequest(string sessionId);

    string Type { get; }
    bool IsStateReady { get; }
     bool IsStateStarting { get; }
     bool IsStateFailed { get; }
     bool IsEnabled {get;}

}



public interface ILLMProcessRunnerFactory
{
    ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? _runnerSemaphore=null);
}

public interface IOpenAIRunnerFactory
{
    ILLMRunner CreateRunner(IServiceProvider serviceProvider,LLMServiceObj serviceObj, SemaphoreSlim? _runnerSemaphore=null);
}
public class LLMProcessRunnerFactory : ILLMProcessRunnerFactory
{
    
    public ILLMRunner CreateRunner(IServiceProvider serviceProvider,LLMServiceObj serviceObj, SemaphoreSlim? _runnerSemaphore)
    {
        return new LLMProcessRunner(serviceProvider.GetRequiredService<ILogger<LLMProcessRunner>>(),serviceProvider.GetRequiredService<ILLMResponseProcessor>(),serviceProvider.GetRequiredService<ISystemParamsHelper >(),serviceObj,_runnerSemaphore!);
    }
}

public class OpenAIRunnerFactory : IOpenAIRunnerFactory
{
   
    public ILLMRunner CreateRunner(IServiceProvider serviceProvider,LLMServiceObj serviceObj, SemaphoreSlim? _runnerSemaphore)
    {
         return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(),serviceProvider.GetRequiredService<ILLMResponseProcessor >(),serviceProvider.GetRequiredService<OpenAIService>(),serviceProvider.GetRequiredService<ISystemParamsHelper >(),serviceObj,_runnerSemaphore!);
    }
}
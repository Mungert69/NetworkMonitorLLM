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
using OpenAI.Managers;


namespace NetworkMonitor.LLM.Services;
// LLMProcessRunner.cs
public interface ILLMRunner
{
    Task StartProcess(LLMServiceObj serviceObj, DateTime currentTime);
    Task SendInputAndGetResponse(LLMServiceObj serviceObj);
     Task RemoveProcess(string sessionId);

    string Type { get; }
    bool IsStateReady { get; }
     bool IsStateStarting { get; }
     bool IsStateFailed { get; }

}



public interface ILLMProcessRunnerFactory
{
    ILLMRunner CreateRunner(IServiceProvider serviceProvider, UserInfo userInfo, SemaphoreSlim? _runnerSemaphore=null);
}

public interface IOpenAIRunnerFactory
{
    ILLMRunner CreateRunner(IServiceProvider serviceProvider,UserInfo userInfo, SemaphoreSlim? _runnerSemaphore=null);
}
public class LLMProcessRunnerFactory : ILLMProcessRunnerFactory
{
    
    public ILLMRunner CreateRunner(IServiceProvider serviceProvider,UserInfo userInfo, SemaphoreSlim? _runnerSemaphore)
    {
        return new LLMProcessRunner(serviceProvider.GetRequiredService<ILogger<LLMProcessRunner>>(),serviceProvider.GetRequiredService<ILLMResponseProcessor>(),serviceProvider.GetRequiredService<ISystemParamsHelper >(),userInfo,_runnerSemaphore);
    }
}

public class OpenAIRunnerFactory : IOpenAIRunnerFactory
{
   
    public ILLMRunner CreateRunner(IServiceProvider serviceProvider,UserInfo userInfo, SemaphoreSlim? _runnerSemaphore)
    {
         return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(),serviceProvider.GetRequiredService<ILLMResponseProcessor >(),serviceProvider.GetRequiredService<OpenAIService>(),serviceProvider.GetRequiredService<ISystemParamsHelper >(),userInfo,_runnerSemaphore);
    }
}
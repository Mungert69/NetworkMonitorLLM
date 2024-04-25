using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
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
    Task StartProcess(string sessionId, DateTime currentTime);
    Task SendInputAndGetResponse(LLMServiceObj serviceObj);
    void RemoveProcess(string sessionId);
}



public interface ILLMProcessRunnerFactory
{
    ILLMRunner CreateRunner(IServiceProvider serviceProvider);
}

public interface IOpenAIRunnerFactory
{
    ILLMRunner CreateRunner(IServiceProvider serviceProvider);
}
public class LLMProcessRunnerFactory : ILLMProcessRunnerFactory
{
    
    public ILLMRunner CreateRunner(IServiceProvider serviceProvider)
    {
        return new LLMProcessRunner(serviceProvider.GetRequiredService<ILogger<LLMProcessRunner>>(),serviceProvider.GetRequiredService<ILLMResponseProcessor>(),serviceProvider.GetRequiredService<ISystemParamsHelper >());
    }
}

public class OpenAIRunnerFactory : IOpenAIRunnerFactory
{
   
    public ILLMRunner CreateRunner(IServiceProvider serviceProvider)
    {
        return new OpenAIRunner(serviceProvider.GetRequiredService<ILogger<OpenAIRunner>>(),serviceProvider.GetRequiredService<ILLMResponseProcessor >(),serviceProvider.GetRequiredService<OpenAIService>());
    }
}
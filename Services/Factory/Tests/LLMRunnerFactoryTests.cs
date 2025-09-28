using System;
using System.Collections.Generic;
using System.Threading;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Coordinator;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LLMRunnerFactoryTests
{
    [Fact]
    public void LoadCount_ClampsToZero()
    {
        var factory = new TestRunnerFactory();
        factory.LoadCount = -5;
        Assert.Equal(0, factory.LoadCount);
    }

    [Fact]
    public void LLMProcessRunnerFactory_CreatesRunner()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<ILogger<LLMProcessRunner>>());
        services.AddSingleton(Mock.Of<ILLMResponseProcessor>());
        services.AddSingleton(new SystemParams { ServiceID = "svc" });
        services.AddSingleton(new MLParams());
        services.AddSingleton(Mock.Of<IAudioGenerator>());
        services.AddSingleton(Mock.Of<ICpuUsageMonitor>());
        services.AddSingleton(Mock.Of<IQueryCoordinator>());
        var provider = services.BuildServiceProvider();

        var factory = new LLMProcessRunnerFactory();
        var runner = factory.CreateRunner(provider, new LLMServiceObj(), new SemaphoreSlim(1, 1), new List<ChatMessage>(), provider.GetRequiredService<ICpuUsageMonitor>());

        Assert.IsType<LLMProcessRunner>(runner);
        Assert.Equal("TestLLM", runner.Type);
    }

    private sealed class TestRunnerFactory : LLMRunnerFactoryBase
    {
        public override ILLMRunner CreateRunner(IServiceProvider serviceProvider, LLMServiceObj serviceObj, SemaphoreSlim? runnerSemaphore, List<ChatMessage> history, ICpuUsageMonitor cpuUsageMonitor)
            => throw new NotImplementedException();
    }
}

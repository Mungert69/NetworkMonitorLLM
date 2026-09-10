using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetworkMonitor.LLM.Services;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Utils.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkMonitor.LLM;

/// <summary>
/// A complete legacy LLM application graph hosted inside the consolidated process.
/// Its singleton registrations, RabbitMQ connections, and configuration are isolated
/// from every other runtime.
/// </summary>
public sealed class ServiceRuntime : IAsyncDisposable
{
    private readonly IServiceProvider _services;
    private readonly ILogger<ServiceRuntime> _logger;
    private readonly CpuUsageMonitor _cpuUsageMonitor;
    private readonly IRabbitRepo _rabbitRepo;
    private readonly IRabbitListener _rabbitListener;
    private readonly ILLMService _llmService;
    private readonly CancellationTokenSource _cancellation;
    private bool _started;

    private ServiceRuntime(string configurationFile, IServiceProvider services)
    {
        ConfigurationFile = configurationFile;
        _services = services;
        _logger = services.GetRequiredService<ILogger<ServiceRuntime>>();
        _cpuUsageMonitor = services.GetRequiredService<CpuUsageMonitor>();
        _rabbitRepo = services.GetRequiredService<IRabbitRepo>();
        _rabbitListener = services.GetRequiredService<IRabbitListener>();
        _llmService = services.GetRequiredService<ILLMService>();
        _cancellation = services.GetRequiredService<CancellationTokenSource>();
        ServiceId = services.GetRequiredService<NetworkMonitor.Objects.SystemParams>().ServiceID
            ?? throw new InvalidOperationException($"Configuration '{configurationFile}' does not define ServiceID.");
    }

    public string ConfigurationFile { get; }
    public string ServiceId { get; }

    public static ServiceRuntime Create(string configurationFile)
    {
        var fullPath = ResolveConfigurationPath(configurationFile);
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Path.GetDirectoryName(fullPath)!)
            .AddJsonFile(Path.GetFileName(fullPath), optional: false)
            .Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        new Startup(configuration).ConfigureServices(services);
        services.AddSingleton<ISystemParamsHelper>(serviceProvider =>
            new SystemParamsHelper(
                configuration,
                serviceProvider.GetRequiredService<ILogger<SystemParamsHelper>>(),
                initializeGlobalConfig: false));
        return new ServiceRuntime(fullPath, services.BuildServiceProvider());
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_started)
            return;

        _logger.LogInformation("Starting isolated LLM runtime {ServiceId} from {ConfigurationFile}", ServiceId, ConfigurationFile);
        await _cpuUsageMonitor.StartAsync(cancellationToken);
        await _rabbitRepo.ConnectAndSetUp(cancellationToken);
        await _rabbitListener.Setup();
        await _llmService.Init();
        _started = true;
    }

    public async ValueTask DisposeAsync()
    {
        _cancellation.Cancel();

        try { await _rabbitListener.Shutdown(); }
        catch (Exception exception) { _logger.LogWarning(exception, "Failed stopping Rabbit listener for {ServiceId}", ServiceId); }

        try { await _rabbitRepo.ShutdownRepo(); }
        catch (Exception exception) { _logger.LogWarning(exception, "Failed stopping Rabbit publisher for {ServiceId}", ServiceId); }

        try { await _cpuUsageMonitor.StopAsync(CancellationToken.None); }
        catch (Exception exception) { _logger.LogWarning(exception, "Failed stopping CPU monitor for {ServiceId}", ServiceId); }

        switch (_services)
        {
            case IAsyncDisposable asyncDisposable:
                await asyncDisposable.DisposeAsync();
                break;
            case IDisposable disposable:
                disposable.Dispose();
                break;
        }
    }

    private static string ResolveConfigurationPath(string configurationFile)
    {
        if (Path.IsPathRooted(configurationFile))
            return configurationFile;

        var workingDirectoryPath = Path.GetFullPath(configurationFile);
        if (File.Exists(workingDirectoryPath))
            return workingDirectoryPath;

        var applicationPath = Path.Combine(AppContext.BaseDirectory, configurationFile);
        if (File.Exists(applicationPath))
            return applicationPath;

        throw new FileNotFoundException("Configured service appsettings file was not found.", configurationFile);
    }
}

public sealed record ServiceRuntimeOptions(IReadOnlyList<string> ConfigurationFiles);

public sealed class MultiRuntimeHostedService : IHostedService
{
    private readonly ServiceRuntimeOptions _options;
    private readonly ILogger<MultiRuntimeHostedService> _logger;
    private readonly List<ServiceRuntime> _runtimes = new();

    public MultiRuntimeHostedService(ServiceRuntimeOptions options, ILogger<MultiRuntimeHostedService> logger)
    {
        _options = options;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var seenServiceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var configurationFile in _options.ConfigurationFiles)
        {
            var runtime = ServiceRuntime.Create(configurationFile);
            if (!seenServiceIds.Add(runtime.ServiceId))
            {
                await runtime.DisposeAsync();
                throw new InvalidOperationException($"Duplicate ServiceID '{runtime.ServiceId}' in consolidated runtime configuration.");
            }

            try
            {
                await runtime.StartAsync(cancellationToken);
                _runtimes.Add(runtime);
            }
            catch
            {
                await runtime.DisposeAsync();
                throw;
            }
        }

        _logger.LogInformation("Started {RuntimeCount} isolated LLM runtimes", _runtimes.Count);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var runtime in _runtimes.AsEnumerable().Reverse())
            await runtime.DisposeAsync();
        _runtimes.Clear();
    }
}

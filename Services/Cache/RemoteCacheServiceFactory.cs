using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace NetworkMonitor.LLM.Services.Cache;

public interface IRemoteCacheServiceFactory
{
    IRemoteCacheService CreateService();
}

public class RemoteCacheServiceFactory : IRemoteCacheServiceFactory
{
    private readonly ISystemParamsHelper _systemParamsHelper;
    private readonly ILogger<RemoteCacheServiceFactory> _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    public RemoteCacheServiceFactory(
        ISystemParamsHelper systemParamsHelper,
        ILogger<RemoteCacheServiceFactory> logger,
        IHttpClientFactory httpClientFactory)
    {
        _systemParamsHelper = systemParamsHelper ?? throw new ArgumentNullException(nameof(systemParamsHelper));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    }

    public IRemoteCacheService CreateService()
    {
        var mlParams = _systemParamsHelper.GetMLParams();
        var remoteCacheConfig = mlParams.RemoteCache;

        if (!remoteCacheConfig.Enabled)
        {
            _logger.LogInformation("Remote cache is disabled");
            return new NoOpRemoteCacheService();
        }

        if (string.Equals(remoteCacheConfig.Type, "Http", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("Creating HTTP remote cache service");
            var httpClient = _httpClientFactory.CreateClient("RemoteCache");
            return new HttpRemoteCacheService(
                httpClient,
                remoteCacheConfig,
                _logger);
        }
        else if (string.Equals(remoteCacheConfig.Type, "S3", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("Creating S3 remote cache service");
            // Note: S3 implementation would need to be updated to use SystemParamsHelper pattern
            // For now, return a placeholder
            return new NoOpRemoteCacheService();
        }
        else
        {
            _logger.LogWarning("Unknown remote cache type: {Type}", remoteCacheConfig.Type);
            return new NoOpRemoteCacheService();
        }
    }
}

// Configuration class that uses SystemParamsHelper pattern
public class RemoteCacheConfig
{
    public bool Enabled { get; set; } = false;
    public string Type { get; set; } = "Http";
    public string BaseUrl { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 30;
    public int RetryAttempts { get; set; } = 3;
}

// No-op implementation for when cache is disabled or unavailable
public class NoOpRemoteCacheService : IRemoteCacheService
{
    public Task<bool> HasContextFileAsync(string fileName, string fileHash)
    {
        return Task.FromResult(false);
    }

    public Task<byte[]> DownloadContextFileAsync(string fileName, string fileHash)
    {
        return Task.FromResult(Array.Empty<byte>());
    }

    public Task UploadContextFileAsync(string fileName, string fileHash, byte[] fileData)
    {
        return Task.CompletedTask;
    }
}
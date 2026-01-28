using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Utils.Helpers;

namespace NetworkMonitor.LLM.Services.Cache;

public interface IRemoteCacheServiceFactory
{
    IRemoteCacheService CreateService();
}

public class RemoteCacheServiceFactory : IRemoteCacheServiceFactory
{
    private readonly ISystemParamsHelper _systemParamsHelper;
    private readonly ILoggerFactory _loggerFactory;

    public RemoteCacheServiceFactory(
        ISystemParamsHelper systemParamsHelper,
        ILoggerFactory loggerFactory)
    {
        _systemParamsHelper = systemParamsHelper ?? throw new ArgumentNullException(nameof(systemParamsHelper));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    public IRemoteCacheService CreateService()
    {
        var mlParams = _systemParamsHelper.GetMLParams();
        var remoteCacheConfig = mlParams.RemoteCache;

        if (!remoteCacheConfig.Enabled)
        {
            var logger = _loggerFactory.CreateLogger<RemoteCacheServiceFactory>();
            logger.LogInformation("Remote cache is disabled");
            return new NoOpRemoteCacheService();
        }

        if (string.Equals(remoteCacheConfig.Type, "Http", StringComparison.OrdinalIgnoreCase))
        {
            var logger = _loggerFactory.CreateLogger<HttpRemoteCacheService>();
            logger.LogInformation("Creating HTTP remote cache service");
            var httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromSeconds(remoteCacheConfig.TimeoutSeconds);
            return new HttpRemoteCacheService(
                httpClient,
                remoteCacheConfig,
                logger);
        }
        else if (string.Equals(remoteCacheConfig.Type, "S3", StringComparison.OrdinalIgnoreCase))
        {
            var logger = _loggerFactory.CreateLogger<RemoteCacheServiceFactory>();
            logger.LogInformation("Creating S3 remote cache service");
            // Note: S3 implementation would need to be updated to use SystemParamsHelper pattern
            // For now, return a placeholder
            return new NoOpRemoteCacheService();
        }
        else
        {
            var logger = _loggerFactory.CreateLogger<RemoteCacheServiceFactory>();
            logger.LogWarning("Unknown remote cache type: {Type}", remoteCacheConfig.Type);
            return new NoOpRemoteCacheService();
        }
    }
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
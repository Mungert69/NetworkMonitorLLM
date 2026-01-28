using System;
using System.IO;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NetworkMonitor.LLM.Services.Cache;

public class S3RemoteCacheService : IRemoteCacheService
{
    private readonly IAmazonS3 _s3Client;
    private readonly string _bucketName;
    private readonly ILogger<S3RemoteCacheService> _logger;

    public S3RemoteCacheService(
        IAmazonS3 s3Client,
        IOptions<S3CacheOptions> options,
        ILogger<S3RemoteCacheService> logger)
    {
        _s3Client = s3Client ?? throw new ArgumentNullException(nameof(s3Client));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        var s3Options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _bucketName = s3Options.BucketName ?? throw new ArgumentException("BucketName is required", nameof(options));
    }

    public async Task<bool> HasContextFileAsync(string fileName, string fileHash)
    {
        if (string.IsNullOrEmpty(fileHash))
        {
            _logger.LogWarning("HasContextFileAsync: fileHash is null or empty");
            return false;
        }

        var key = GetObjectKey(fileHash);
        
        try
        {
            var request = new GetObjectMetadataRequest
            {
                BucketName = _bucketName,
                Key = key
            };
            
            await _s3Client.GetObjectMetadataAsync(request);
            return true;
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check context file existence for hash {FileHash}", fileHash);
            return false;
        }
    }

    public async Task<byte[]> DownloadContextFileAsync(string fileName, string fileHash)
    {
        if (string.IsNullOrEmpty(fileHash))
        {
            throw new ArgumentException("File hash cannot be null or empty", nameof(fileHash));
        }

        var key = GetObjectKey(fileHash);
        
        try
        {
            var request = new GetObjectRequest
            {
                BucketName = _bucketName,
                Key = key
            };
            
            using var response = await _s3Client.GetObjectAsync(request);
            using var memoryStream = new MemoryStream();
            await response.ResponseStream.CopyToAsync(memoryStream);
            
            _logger.LogInformation("Successfully downloaded context file {FileName} (hash: {FileHash}) from S3", fileName, fileHash);
            return memoryStream.ToArray();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to download context file {FileName} (hash: {FileHash}) from S3", fileName, fileHash);
            throw;
        }
    }

    public async Task UploadContextFileAsync(string fileName, string fileHash, byte[] fileData)
    {
        if (string.IsNullOrEmpty(fileHash))
        {
            throw new ArgumentException("File hash cannot be null or empty", nameof(fileHash));
        }

        if (fileData == null || fileData.Length == 0)
        {
            throw new ArgumentException("File data cannot be null or empty", nameof(fileData));
        }

        var key = GetObjectKey(fileHash);
        
        try
        {
            var request = new PutObjectRequest
            {
                BucketName = _bucketName,
                Key = key,
                InputStream = new MemoryStream(fileData),
                ContentType = "application/octet-stream"
            };
            
            await _s3Client.PutObjectAsync(request);
            _logger.LogInformation("Successfully uploaded context file {FileName} (hash: {FileHash}) to S3", fileName, fileHash);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to upload context file {FileName} (hash: {FileHash}) to S3", fileName, fileHash);
            throw;
        }
    }

    private string GetObjectKey(string fileHash)
    {
        return $"llm-context/{fileHash}.gguf";
    }
}

public class S3CacheOptions
{
    public string BucketName { get; set; } = string.Empty;
    public string Region { get; set; } = "us-east-1";
    public string AccessKey { get; set; } = string.Empty;
    public string SecretKey { get; set; } = string.Empty;
}
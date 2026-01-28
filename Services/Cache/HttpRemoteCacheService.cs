using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NetworkMonitor.LLM.Services.Cache;

public class HttpRemoteCacheService : IRemoteCacheService
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private readonly string _apiKey;
    private readonly int _timeoutSeconds;
    private readonly int _retryAttempts;
    private readonly ILogger<HttpRemoteCacheService> _logger;

    public HttpRemoteCacheService(
        HttpClient httpClient,
        RemoteCacheConfig config,
        ILogger<HttpRemoteCacheService> logger)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        _baseUrl = config.BaseUrl ?? throw new ArgumentException("BaseUrl is required");
        _apiKey = config.ApiKey ?? throw new ArgumentException("ApiKey is required");
        _timeoutSeconds = config.TimeoutSeconds > 0 ? config.TimeoutSeconds : 30;
        _retryAttempts = config.RetryAttempts > 0 ? config.RetryAttempts : 3;
        
        // Configure HttpClient timeout
        _httpClient.Timeout = TimeSpan.FromSeconds(_timeoutSeconds);
    }

    public async Task<bool> HasContextFileAsync(string fileName, string fileHash)
    {
        if (string.IsNullOrEmpty(fileHash))
        {
            _logger.LogWarning("HasContextFileAsync: fileHash is null or empty");
            return false;
        }

        var request = new HttpRequestMessage(HttpMethod.Head, $"{_baseUrl}/cache/{fileHash}");
        AddAuthHeaders(request);

        try
        {
            var response = await ExecuteWithRetryAsync(() => _httpClient.SendAsync(request));
            return response.IsSuccessStatusCode;
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

        var request = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}/cache/{fileHash}");
        AddAuthHeaders(request);

        try
        {
            var response = await ExecuteWithRetryAsync(() => _httpClient.SendAsync(request));
            response.EnsureSuccessStatusCode();
            
            var fileData = await response.Content.ReadAsByteArrayAsync();
            _logger.LogInformation("Successfully downloaded context file {FileName} (hash: {FileHash})", fileName, fileHash);
            return fileData;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to download context file {FileName} (hash: {FileHash})", fileName, fileHash);
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

        var content = new ByteArrayContent(fileData);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        
        var request = new HttpRequestMessage(HttpMethod.Put, $"{_baseUrl}/cache/{fileHash}")
        {
            Content = content
        };
        AddAuthHeaders(request);

        try
        {
            var response = await ExecuteWithRetryAsync(() => _httpClient.SendAsync(request));
            response.EnsureSuccessStatusCode();
            _logger.LogInformation("Successfully uploaded context file {FileName} (hash: {FileHash})", fileName, fileHash);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to upload context file {FileName} (hash: {FileHash})", fileName, fileHash);
            throw;
        }
    }

    private void AddAuthHeaders(HttpRequestMessage request)
    {
        if (!string.IsNullOrEmpty(_apiKey))
        {
            request.Headers.Add("X-API-Key", _apiKey);
        }
    }

    private async Task<HttpResponseMessage> ExecuteWithRetryAsync(Func<Task<HttpResponseMessage>> operation)
    {
        Exception lastException = null;

        for (int attempt = 1; attempt <= _retryAttempts; attempt++)
        {
            try
            {
                var response = await operation();
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }
                
                // If not successful, throw to trigger retry
                response.EnsureSuccessStatusCode();
                return response; // This won't be reached if EnsureSuccessStatusCode throws
            }
            catch (Exception ex)
            {
                lastException = ex;
                
                if (attempt == _retryAttempts)
                {
                    _logger.LogWarning("Operation failed after {RetryAttempts} attempts. Last error: {ErrorMessage}", 
                        _retryAttempts, ex.Message);
                    break;
                }
                
                var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)); // Exponential backoff
                _logger.LogWarning("Operation failed on attempt {Attempt} of {RetryAttempts}. Retrying in {Delay} seconds. Error: {ErrorMessage}", 
                    attempt, _retryAttempts, delay.TotalSeconds, ex.Message);
                
                await Task.Delay(delay);
            }
        }

        throw lastException;
    }
}

public class RemoteCacheOptions
{
    public bool Enabled { get; set; } = false;
    public string Type { get; set; } = "Http";
    public string BaseUrl { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 30;
    public int RetryAttempts { get; set; } = 3;
}
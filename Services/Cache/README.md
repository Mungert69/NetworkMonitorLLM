# Remote Cache Services for LLM Context Files

This directory contains the implementation of remote caching for expensive LLM context files in the NetworkMonitorLLM system.

## Overview

The remote cache system addresses the problem of expensive LLM context file generation in Docker containers without persistent volumes. When containers restart, these expensive-to-build context files are lost, causing significant startup delays.

## Architecture

### Core Components

1. **IRemoteCacheService** - Interface defining cache operations
2. **HttpRemoteCacheService** - HTTP-based cache implementation (production-ready)
3. **S3RemoteCacheService** - S3-compatible object storage implementation (code-only)
4. **CachedSystemPromptWriter** - System prompt writer with cache integration
5. **EnhancedSystemPromptWriter** - Enhanced version with upload capabilities

### Cache Flow

```
Container Startup
    ↓
SystemPromptWriter.EnsurePromptFile()
    ↓
Check if context file exists locally
    ↓
If NOT exists → Check remote cache
    ↓
If exists remotely → Download and restore
    ↓
If NOT exists remotely → Build locally
    ↓
After successful build → Upload to remote cache
```

## Configuration

### appsettings.json

```json
{
  "RemoteCache": {
    "Enabled": true,
    "Type": "Http",
    "BaseUrl": "https://your-cache-server.com/api",
    "ApiKey": "your-api-key-here",
    "TimeoutSeconds": 30,
    "RetryAttempts": 3
  },
  "S3Cache": {
    "BucketName": "your-s3-bucket-name",
    "Region": "us-east-1",
    "AccessKey": "your-s3-access-key",
    "SecretKey": "your-s3-secret-key"
  }
}
```

## Usage

### 1. Enable Remote Cache

Set `"RemoteCache": { "Enabled": true }` in your configuration.

### 2. Configure Cache Server

Point `"BaseUrl"` to your remote cache server endpoint.

### 3. Set API Key

Provide your authentication key for the cache server.

## Cache Server Implementation

### Simple HTTP Cache Server

A basic cache server can be implemented with these endpoints:

- `HEAD /api/cache/{fileHash}` - Check if file exists
- `GET /api/cache/{fileHash}` - Download file
- `PUT /api/cache/{fileHash}` - Upload file

### Example Cache Server (C#)

```csharp
[ApiController]
[Route("api/cache")]
public class CacheController : ControllerBase
{
    [HttpHead("{fileHash}")]
    public IActionResult CheckFile(string fileHash)
    {
        var filePath = GetFilePath(fileHash);
        return System.IO.File.Exists(filePath) ? Ok() : NotFound();
    }
    
    [HttpGet("{fileHash}")]
    public IActionResult DownloadFile(string fileHash)
    {
        var filePath = GetFilePath(fileHash);
        if (!System.IO.File.Exists(filePath))
            return NotFound();
            
        var fileBytes = System.IO.File.ReadAllBytes(filePath);
        return File(fileBytes, "application/octet-stream", $"{fileHash}.gguf");
    }
    
    [HttpPut("{fileHash}")]
    public async Task<IActionResult> UploadFile(string fileHash)
    {
        var filePath = GetFilePath(fileHash);
        
        using var memoryStream = new MemoryStream();
        await Request.Body.CopyToAsync(memoryStream);
        
        await System.IO.File.WriteAllBytesAsync(filePath, memoryStream.ToArray());
        return Ok();
    }
}
```

## File Naming Convention

Context files are named using SHA256 hashes of their prompt content:

```
context-{prompt-hash}.gguf
```

This ensures that identical prompts always generate the same cache key, enabling efficient sharing across containers.

## Performance Benefits

### Before Cache Implementation
- **First container startup**: 5-10 minutes (context building)
- **Subsequent startups**: 5-10 minutes (rebuild)
- **Multiple containers**: Each builds independently

### After Cache Implementation
- **First container startup**: 5-10 minutes (build + upload)
- **Subsequent startups**: 30-60 seconds (download)
- **Multiple containers**: Share cached files

## Error Handling

The cache system includes robust error handling:

1. **Graceful degradation**: If remote cache is unavailable, falls back to local building
2. **Retry logic**: Automatic retries with exponential backoff
3. **Timeout handling**: Configurable timeouts for all operations
4. **Logging**: Comprehensive logging for debugging and monitoring

## Monitoring

Monitor cache effectiveness through:

1. **Cache hit rate**: Percentage of files restored from cache
2. **Download times**: Time taken to restore files
3. **Upload times**: Time taken to upload new files
4. **Error rates**: Failed operations and their causes

## Security Considerations

1. **Authentication**: Use API keys or other authentication mechanisms
2. **Encryption**: Ensure HTTPS for all cache operations
3. **Access control**: Limit access to authorized containers only
4. **File validation**: Verify file integrity after download

## Deployment

### Docker Compose Example

```yaml
version: '3.8'
services:
  network-monitor-llm:
    build: .
    environment:
      - REMOTE_CACHE__ENABLED=true
      - REMOTE_CACHE__BASEURL=http://cache-server:5000/api
      - REMOTE_CACHE__APIKEY=your-api-key
  
  cache-server:
    image: your-cache-server:latest
    environment:
      - API_KEY=your-api-key
      - CACHE_DIRECTORY=/app/cache
    volumes:
      - cache-data:/app/cache

volumes:
  cache-data:
```

## Troubleshooting

### Common Issues

1. **Cache server unreachable**: Check network connectivity and API key
2. **File not found**: Verify cache server has the requested file
3. **Upload failures**: Check cache server write permissions
4. **Timeout errors**: Increase timeout settings in configuration

### Debug Logging

Enable debug logging to troubleshoot cache operations:

```json
{
  "Logging": {
    "LogLevel": {
      "NetworkMonitor.LLM.Services.Cache": "Debug"
    }
  }
}
```

## Future Enhancements

1. **Multi-region support**: Deploy cache servers in multiple regions
2. **Compression**: Compress files during transfer to reduce bandwidth
3. **Cache cleanup**: Implement automatic cleanup of old cache files
4. **Metrics**: Add Prometheus metrics for monitoring
5. **CDN integration**: Use CDN for faster global access
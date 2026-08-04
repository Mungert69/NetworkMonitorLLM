using System;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class RedisHistoryStorageTests
{
    [Fact]
    public void BuildConfiguration_SetsExpectedOptions()
    {
        var options = RedisHistoryStorage.BuildConfiguration("localhost:1234", "secret");

        var endpoints = options.EndPoints;
        Assert.NotNull(endpoints);
        Assert.Contains(endpoints, e => e?.ToString()?.Contains("localhost:1234") == true);
        Assert.Equal("secret", options.Password);
        Assert.True(options.Ssl);
        Assert.Equal("admin", options.User);
        Assert.Equal(TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(options.ConnectTimeout));
        Assert.Equal(TimeSpan.FromSeconds(120), TimeSpan.FromMilliseconds(options.SyncTimeout));
        Assert.Equal(TimeSpan.FromSeconds(120), TimeSpan.FromMilliseconds(options.AsyncTimeout));
    }

    [Fact]
    public async Task LoadHistoryAsync_WithEmptySessionId_Throws()
    {
        var instance = CreateInstance();
        await Assert.ThrowsAsync<System.ArgumentException>(() => instance.LoadHistoryAsync(""));
    }

    [Fact]
    public async Task DeleteHistoryAsync_WithEmptySessionId_Throws()
    {
        var instance = CreateInstance();
        await Assert.ThrowsAsync<System.ArgumentException>(() => instance.DeleteHistoryAsync(" "));
    }

    private static RedisHistoryStorage CreateInstance()
    {
        var instance = (RedisHistoryStorage)RuntimeHelpers.GetUninitializedObject(typeof(RedisHistoryStorage));
        var loggerField = typeof(RedisHistoryStorage).GetField("_logger", BindingFlags.NonPublic | BindingFlags.Instance)!;
        loggerField.SetValue(instance, Microsoft.Extensions.Logging.Abstractions.NullLogger<RedisHistoryStorage>.Instance);
        return instance;
    }
}

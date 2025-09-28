using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
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
        var instance = (RedisHistoryStorage)FormatterServices.GetUninitializedObject(typeof(RedisHistoryStorage));
        var method = typeof(RedisHistoryStorage).GetMethod("BuildConfiguration", BindingFlags.NonPublic | BindingFlags.Instance)!;

        var options = (ConfigurationOptions)method.Invoke(instance, new object[] { "localhost:1234", "secret" })!;

        Assert.Contains(options.EndPoints, e => e.ToString().Contains("localhost:1234"));
        Assert.Equal("secret", options.Password);
        Assert.True(options.Ssl);
        Assert.Equal("admin", options.User);
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
        var instance = (RedisHistoryStorage)FormatterServices.GetUninitializedObject(typeof(RedisHistoryStorage));
        var loggerField = typeof(RedisHistoryStorage).GetField("_logger", BindingFlags.NonPublic | BindingFlags.Instance)!;
        loggerField.SetValue(instance, Microsoft.Extensions.Logging.Abstractions.NullLogger<RedisHistoryStorage>.Instance);
        return instance;
    }
}

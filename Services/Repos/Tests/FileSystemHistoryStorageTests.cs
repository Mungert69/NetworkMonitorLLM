using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class FileSystemHistoryStorageTests : IAsyncLifetime
{
    private readonly string _tempDir;
    private readonly FileSystemHistoryStorage _storage;

    public FileSystemHistoryStorageTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"history-{System.Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _storage = new FileSystemHistoryStorage();

        var field = typeof(FileSystemHistoryStorage).GetField("_storagePath", BindingFlags.NonPublic | BindingFlags.Instance)!;
        field.SetValue(_storage, _tempDir);
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public Task DisposeAsync()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task SaveAndLoadHistory_RoundTripsThroughDisk()
    {
        var history = new HistoryDisplayName
        {
            SessionId = "abc123",
            StartUnixTime = 111,
            UserId = "user42",
            Name = "Session name",
            History = new() { ChatMessage.FromUser("hello") }
        };

        await _storage.SaveHistoryAsync(history);
        var loaded = await _storage.LoadHistoryAsync("abc123");

        Assert.NotNull(loaded);
        Assert.Equal(history.SessionId, loaded!.SessionId);
        Assert.Single(loaded.History);
        Assert.Equal("hello", loaded.History[0].Content);
    }

    [Fact]
    public async Task LoadAllSessionsAsync_ReturnsSavedSessions()
    {
        var history = new HistoryDisplayName
        {
            SessionId = "s1",
            StartUnixTime = 1,
            UserId = "u1",
            Name = "First"
        };
        await _storage.SaveHistoryAsync(history);

        var sessions = await _storage.LoadAllSessionsAsync();

        Assert.True(sessions.ContainsKey("s1"));
        Assert.Equal("First", sessions["s1"].HistoryDisplayName.Name);
    }

    [Fact]
    public async Task GetHistoryDisplayNamesAsync_FiltersByUserId()
    {
        await _storage.SaveHistoryAsync(new HistoryDisplayName { SessionId = "s1_userA_extra", StartUnixTime = 1, UserId = "userA", Name = "A" });
        await _storage.SaveHistoryAsync(new HistoryDisplayName { SessionId = "s2_userB_extra", StartUnixTime = 2, UserId = "userB", Name = "B" });

        var results = await _storage.GetHistoryDisplayNamesAsync("userA");

        Assert.Single(results);
        Assert.Equal("A", results[0].Name);
    }

    [Fact]
    public async Task DeleteHistoryAsync_RemovesMatchingFiles()
    {
        await _storage.SaveHistoryAsync(new HistoryDisplayName { SessionId = "delme", StartUnixTime = 1, UserId = "user" });
        Assert.NotEmpty(Directory.GetFiles(_tempDir));

        await _storage.DeleteHistoryAsync("delme");

        Assert.Empty(Directory.GetFiles(_tempDir));
    }
}

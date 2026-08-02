using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace NetworkMonitor.LLM.Services;

public interface ILocalLlmSessionStore
{
    Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync();
    Task<HistoryDisplayName?> LoadAsync(string sessionId);
    Task SaveAsync(HistoryDisplayName session);
    Task DeleteAsync(string sessionId);
}

public sealed class LocalLlmSessionStore : ILocalLlmSessionStore
{
    private readonly string _rootPath;

    public LocalLlmSessionStore(string? rootPath = null)
    {
        _rootPath = rootPath
            ?? Environment.GetEnvironmentVariable("LOCAL_LLM_SESSION_PATH")
            ?? "/data/networkmonitor/sessions";
    }

    public async Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
    {
        var sessions = new ConcurrentDictionary<string, Session>();
        if (!Directory.Exists(_rootPath)) return sessions;

        foreach (var path in Directory.EnumerateFiles(_rootPath, "*.json"))
        {
            try
            {
                var savedSession = JsonConvert.DeserializeObject<HistoryDisplayName>(await File.ReadAllTextAsync(path));
                if (savedSession != null)
                {
                    sessions.TryAdd(savedSession.SessionId, new Session
                    {
                        FullSessionId = savedSession.SessionId,
                        HistoryDisplayName = savedSession
                    });
                }
            }
            catch (JsonException)
            {
                // Leave an unreadable session file in place for manual recovery.
            }
        }

        return sessions;
    }

    public async Task<HistoryDisplayName?> LoadAsync(string sessionId)
    {
        var path = GetPath(sessionId);
        if (!File.Exists(path)) return null;
        return JsonConvert.DeserializeObject<HistoryDisplayName>(await File.ReadAllTextAsync(path));
    }

    public async Task SaveAsync(HistoryDisplayName session)
    {
        Directory.CreateDirectory(_rootPath);
        var path = GetPath(session.SessionId);
        var temporaryPath = path + ".tmp";
        var json = JsonConvert.SerializeObject(session);
        await File.WriteAllTextAsync(temporaryPath, json);
        File.Move(temporaryPath, path, overwrite: true);
    }

    public Task DeleteAsync(string sessionId)
    {
        var path = GetPath(sessionId);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }

    private string GetPath(string sessionId)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(sessionId));
        return Path.Combine(_rootPath, Convert.ToHexString(bytes).ToLowerInvariant() + ".json");
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services;

public interface IHistoryStorage
{
    Task SaveHistoryAsync(HistoryDisplayName historyDisplayName);
    Task<HistoryDisplayName> LoadHistoryAsync(string sessionId);
    Task DeleteHistoryAsync(string sessionId);
    Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId);
}

public class FileSystemHistoryStorage : IHistoryStorage
{
    private readonly string _storagePath = "histories";

    public FileSystemHistoryStorage()
    {
        Directory.CreateDirectory(_storagePath); // Ensure the directory exists
    }

    public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId)
    {
        var historyDisplayNames = new List<HistoryDisplayName>();
        var files = Directory.GetFiles(_storagePath, $"*¿*¿{userId}¿*.json");

        foreach (var file in files)
        {
            var json = await File.ReadAllTextAsync(file);
            var historyDisplayName = JsonSerializer.Deserialize<HistoryDisplayName>(json);
            if (historyDisplayName != null)
            {
                historyDisplayNames.Add(historyDisplayName);
            }
        }

        return historyDisplayNames;
    }

    public async Task SaveHistoryAsync(HistoryDisplayName historyDisplayName)
    {
        var filePath = Path.Combine(_storagePath, $"{historyDisplayName.StartUnixTime}¿{historyDisplayName.SessionId}.json");
        var json = JsonSerializer.Serialize(historyDisplayName);
        await File.WriteAllTextAsync(filePath, json);
    }

    public async Task<HistoryDisplayName> LoadHistoryAsync(string sessionId)
    {
        var files = Directory.GetFiles(_storagePath, $"*¿{sessionId}.json");
        if (files.Length == 0)
        {
            return null;
        }

        var filePath = files[0]; // Assuming sessionId is unique
        var json = await File.ReadAllTextAsync(filePath);
        return JsonSerializer.Deserialize<HistoryDisplayName>(json);
    }

    public async Task DeleteHistoryAsync(string sessionId)
    {
        var files = Directory.GetFiles(_storagePath, $"*¿{sessionId}.json");
        if (files.Length > 0)
        {
            var filePath = files[0]; // Assuming sessionId is unique
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }
    }
}
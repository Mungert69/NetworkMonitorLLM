using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services;
public interface IHistoryStorage
{
    Task SaveHistoryAsync(string sessionId, List<ChatMessage> history);
    Task<List<ChatMessage>> LoadHistoryAsync(string sessionId);
    Task DeleteHistoryAsync(string sessionId);
}
public class FileSystemHistoryStorage : IHistoryStorage
{
    private readonly string _storagePath="histories";

    public FileSystemHistoryStorage()
    {
        Directory.CreateDirectory(_storagePath); // Ensure the directory exists
    }

    public async Task SaveHistoryAsync(string sessionId, List<ChatMessage> history)
    {
        var filePath = Path.Combine(_storagePath, $"{sessionId}.json");
        var json = JsonSerializer.Serialize(history);
        await File.WriteAllTextAsync(filePath, json);
    }

    public async Task<List<ChatMessage>> LoadHistoryAsync(string sessionId)
    {
        var filePath = Path.Combine(_storagePath, $"{sessionId}.json");
        if (!File.Exists(filePath))
        {
            return new List<ChatMessage>();
        }

        var json = await File.ReadAllTextAsync(filePath);
        return JsonSerializer.Deserialize<List<ChatMessage>>(json);
    }

    public async Task DeleteHistoryAsync(string sessionId)
    {
        var filePath = Path.Combine(_storagePath, $"{sessionId}.json");
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }
    }
}
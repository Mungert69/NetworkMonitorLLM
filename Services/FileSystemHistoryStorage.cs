using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services;

public interface IHistoryStorage
{
    Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync();
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
    public async Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
    {
        var sessions = new ConcurrentDictionary<string, Session>();

        // Get all history files in the storage directory
        var files = Directory.GetFiles(_storagePath, "*.json");

        foreach (var file in files)
        {
            try
            {
                // Read and deserialize the file
                var json = await File.ReadAllTextAsync(file);
                var historyDisplayName = JsonConvert.DeserializeObject<HistoryDisplayName>(json);

                if (historyDisplayName != null)
                {
                    // Create a new Session object
                    var session = new Session
                    {
                        HistoryDisplayName = historyDisplayName,
                        Runner = null // Set the runner if applicable
                    };

                    // Add the session to the dictionary
                    sessions.TryAdd(historyDisplayName.SessionId, session);
                }
            }
            catch (Exception ex)
            {
                // Log or handle the error as needed
                Console.WriteLine($"Error loading session from file {file}: {ex.Message}");
            }
        }

        return sessions;
    }
    public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId)
    {
        var historyDisplayNames = new List<HistoryDisplayName>();
        var files = Directory.GetFiles(_storagePath, $"*_{userId}_*.json");

        foreach (var file in files)
        {
            var json = await File.ReadAllTextAsync(file);
            
              var historyDisplayName = JsonConvert.DeserializeObject<HistoryDisplayName>(json); 
         if (historyDisplayName != null)
            {
                historyDisplayNames.Add(historyDisplayName);
            }
        }

        return historyDisplayNames;
    }

    public async Task SaveHistoryAsync(HistoryDisplayName historyDisplayName)
    {
        var filePath = Path.Combine(_storagePath, $"{historyDisplayName.StartUnixTime}_{historyDisplayName.SessionId}.json");
       var json = JsonConvert.SerializeObject(historyDisplayName, new JsonSerializerSettings
{
    ContractResolver = new CamelCasePropertyNamesContractResolver(),
    Formatting = Formatting.Indented
});

       await File.WriteAllTextAsync(filePath, json);
    }

    public async Task<HistoryDisplayName> LoadHistoryAsync(string sessionId)
    {
    var searchPattern = $"*_{sessionId}.json";

    // Get all files matching the pattern
    var files = Directory.GetFiles(_storagePath, searchPattern);

        if (files.Length == 0)
        {
            return null;
        }

        var filePath = files[0]; // Assuming sessionId is unique
        var json = await File.ReadAllTextAsync(filePath);
         // Deserialize using Newtonsoft.Json
        return JsonConvert.DeserializeObject<HistoryDisplayName>(json); 
    }

    public async Task DeleteHistoryAsync(string sessionId)
    {
        var files = Directory.GetFiles(_storagePath, $"*_{sessionId}.json");
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
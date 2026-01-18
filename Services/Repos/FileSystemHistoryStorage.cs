using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Threading.Tasks;
using NetworkMonitor.Objects;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services;

public interface IHistoryStorage
{
    Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync();
    Task SaveHistoryAsync(HistoryDisplayName historyDisplayName);
    Task<HistoryDisplayName?> LoadHistoryAsync(string sessionId);
    Task DeleteHistoryAsync(string sessionId);
    Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId, string? serviceId = null);
}

public class FileSystemHistoryStorage : IHistoryStorage
{
    private readonly string _storagePath;

    public FileSystemHistoryStorage()
    {
        _storagePath = BuildStoragePath(null);
        Directory.CreateDirectory(_storagePath); // Ensure the directory exists
    }

    public FileSystemHistoryStorage(SystemParams systemParams)
    {
        _storagePath = BuildStoragePath(systemParams.ServiceID);
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
    public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId, string? serviceId = null)
    {
        var historyDisplayNames = new List<HistoryDisplayName>();
        var storagePath = serviceId == null ? _storagePath : BuildStoragePath(serviceId);
        if (!Directory.Exists(storagePath))
        {
            return historyDisplayNames;
        }
        var files = Directory.GetFiles(storagePath, $"*_{userId}_*.json");

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

    public async Task<HistoryDisplayName?> LoadHistoryAsync(string sessionId)
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
    var files = await Task.Run(() => Directory.GetFiles(_storagePath, $"*_{sessionId}.json"));

    foreach (var filePath in files)
    {
        if (File.Exists(filePath))
        {
            await Task.Run(() => File.Delete(filePath)); // Offload file deletion to another thread
        }
    }
}

    private static string BuildStoragePath(string? serviceId)
    {
        if (string.IsNullOrWhiteSpace(serviceId))
        {
            return "data";
        }
        var invalidChars = Path.GetInvalidFileNameChars();
        var cleaned = new string(serviceId.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray());
        if (string.IsNullOrWhiteSpace(cleaned))
        {
            return "data";
        }
        return Path.Combine("data", cleaned);
    }

}

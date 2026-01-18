using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects;

namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    ///  NOTE this code does not work as the urls are not exposed by huggingface datasets api
    /// </summary>
    public class HuggingFaceDatasetStorage : IHistoryStorage
    {
        private readonly string _dataRepoId;
        private readonly string _token;
        private readonly HttpClient _httpClient;
        private readonly string _serviceId;
        private const string ApiBaseUrl = "https://huggingface.co/api/datasets/";

        public HuggingFaceDatasetStorage(MLParams mlParams, SystemParams systemParams)
        {
            _dataRepoId=mlParams.DataRepoId;
            _token=mlParams.HFToken;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_token}");
            _serviceId = SanitizeServiceId(systemParams.ServiceID);
        }

        public async Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
        {
            var sessions = new ConcurrentDictionary<string, Session>();
            
            try
            {
                var files = await ListFilesInRepo();
                var jsonFiles = files.Where(f =>
                    f.StartsWith($"{_serviceId}_", StringComparison.OrdinalIgnoreCase) &&
                    f.EndsWith(".json", StringComparison.OrdinalIgnoreCase));

                foreach (var file in jsonFiles)
                {
                    try
                    {
                        var content = await DownloadFile(file);
                        var historyDisplayName = JsonConvert.DeserializeObject<HistoryDisplayName>(content);

                        if (historyDisplayName != null)
                        {
                            sessions.TryAdd(historyDisplayName.SessionId, new Session
                            {
                                HistoryDisplayName = historyDisplayName,
                                Runner = null
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error loading session from file {file}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error listing files: {ex.Message}");
            }

            return sessions;
        }

        public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId)
        {
            var historyDisplayNames = new List<HistoryDisplayName>();
            
            try
            {
                var files = await ListFilesInRepo();
                var userFiles = files.Where(f =>
                    f.Contains($"{_serviceId}_", StringComparison.OrdinalIgnoreCase) &&
                    f.Contains($"_{userId}_") &&
                    f.EndsWith(".json", StringComparison.OrdinalIgnoreCase));

                foreach (var file in userFiles)
                {
                    try
                    {
                        var content = await DownloadFile(file);
                        var historyDisplayName = JsonConvert.DeserializeObject<HistoryDisplayName>(content);
                        if (historyDisplayName != null)
                        {
                            historyDisplayNames.Add(historyDisplayName);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error loading file {file}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error listing files: {ex.Message}");
            }

            return historyDisplayNames;
        }

        public async Task SaveHistoryAsync(HistoryDisplayName historyDisplayName)
        {
            var fileName = $"{_serviceId}_{historyDisplayName.StartUnixTime}_{historyDisplayName.SessionId}.json";
            var json = JsonConvert.SerializeObject(historyDisplayName, new JsonSerializerSettings
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver(),
                Formatting = Formatting.Indented
            });

            await UploadFile(fileName, json);
        }

        public async Task<HistoryDisplayName?> LoadHistoryAsync(string sessionId)
        {
            try
            {
                var files = await ListFilesInRepo();
                var matchingFiles = files
                    .Where(f =>
                        f.StartsWith($"{_serviceId}_", StringComparison.OrdinalIgnoreCase) &&
                        f.EndsWith($"_{sessionId}.json", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchingFiles.Count == 0) return null;

                var content = await DownloadFile(matchingFiles.First());
                return JsonConvert.DeserializeObject<HistoryDisplayName>(content);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading session {sessionId}: {ex.Message}");
                return null;
            }
        }

        public async Task DeleteHistoryAsync(string sessionId)
        {
            try
            {
                var files = await ListFilesInRepo();
                var matchingFiles = files.Where(f =>
                    f.StartsWith($"{_serviceId}_", StringComparison.OrdinalIgnoreCase) &&
                    f.EndsWith($"_{sessionId}.json", StringComparison.OrdinalIgnoreCase));

                foreach (var file in matchingFiles)
                {
                    await DeleteFile(file);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting session {sessionId}: {ex.Message}");
            }
        }

        private async Task<List<string>> ListFilesInRepo()
        {
            var response = await _httpClient.GetAsync($"{ApiBaseUrl}{_dataRepoId}/tree/main");
            response.EnsureSuccessStatusCode();
            
            var content = await response.Content.ReadAsStringAsync();
            var files = JsonConvert.DeserializeObject<List<HfFileInfo>>(content) ?? new List<HfFileInfo>();
            return files
                .Select(f => f.Path)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .ToList();
        }

        private async Task<string> DownloadFile(string filePath)
        {
            var response = await _httpClient.GetAsync($"{ApiBaseUrl}{_dataRepoId}/resolve/main/{filePath}");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        private async Task UploadFile(string fileName, string content)
        {
            var request = new HttpRequestMessage(HttpMethod.Put, $"{ApiBaseUrl}{_dataRepoId}/write/main/{fileName}")
            {
                Content = new StringContent(content)
            };
            
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }

        private async Task DeleteFile(string filePath)
        {
            var response = await _httpClient.DeleteAsync($"{ApiBaseUrl}{_dataRepoId}/delete/main/{filePath}");
            response.EnsureSuccessStatusCode();
        }

        private class HfFileInfo
        {
            public string Path { get; set; } = string.Empty;
            public string Type { get; set; } = string.Empty;
        }

        private static string SanitizeServiceId(string? serviceId)
        {
            if (string.IsNullOrWhiteSpace(serviceId)) return "default";
            var invalidChars = System.IO.Path.GetInvalidFileNameChars();
            var cleaned = new string(serviceId.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray());
            return string.IsNullOrWhiteSpace(cleaned) ? "default" : cleaned;
        }
    }
}

using System;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Threading.Tasks;
using System.Linq;
using System.IO;

using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Utils.Helpers;

namespace NetworkMonitor.LLM.Services
{
    public class AudioGenerator : IAudioGenerator
    {
        private string _apiEndpoint = "";
        private string _baseUrl = "";
        private string _outputDirectory = ""; // Centralized property
        private string _frontendUrl = "";
        private ILogger _logger;
        public AudioGenerator(ILogger<OpenAIRunner> logger, ISystemParamsHelper systemParamsHelper)
        {
            _apiEndpoint = systemParamsHelper.GetSystemParams().AudioServiceUrl + "/generate_audio";
            _baseUrl = systemParamsHelper.GetSystemParams().AudioServiceUrl + "/files/";
            _outputDirectory = systemParamsHelper.GetSystemParams().AudioServiceOutputDir;
            _frontendUrl = systemParamsHelper.GetSystemParams().FrontEndUrl;
            _logger = logger;
        }


        public async Task<string> AudioForResponse(string text)
        {
            try
            {

                var payload = new
                {
                    text,
                    output_dir = _outputDirectory
                };

                var outputPath = await PostToAudioApiAsync(payload);

                if (!string.IsNullOrEmpty(outputPath))
                {
                    string fileName = outputPath.Replace(_outputDirectory, "").TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                    string returnUrl = _baseUrl + fileName;
                    _logger.LogInformation($"Audio generated successfully: {returnUrl}");
                    return returnUrl;
                }

                _logger.LogError("Audio generation failed for single response.");
                return string.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating audio: {ex.Message}");
                return string.Empty;
            }
        }

        public List<string> GetChunksFromText(string text, int maxLength = 500)
        {
            // Split text into paragraphs or logical chunks
            var chunks = text.Split(new[] { "\n\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                             .Select(chunk => chunk.Trim())
                             .Where(chunk => !string.IsNullOrWhiteSpace(chunk))
                             .ToList();

            var resultChunks = new List<string>();

            foreach (var chunk in chunks)
            {
                if (chunk.Length > maxLength)
                {
                    // Further split large chunks if necessary
                    resultChunks.AddRange(SplitByWordLimit(chunk, maxLength));
                }
                else
                {
                    resultChunks.Add(chunk);
                }
            }

            return resultChunks;
        }

        public async Task<List<string>> AudioForResponseChunks(string text)
        {
            var audioUrls = new List<string>();

            try
            {
                // Split text into paragraphs or logical chunks
                var chunks = text.Split(new[] { "\n\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                                 .Select(chunk => chunk.Trim())
                                 .Where(chunk => !string.IsNullOrWhiteSpace(chunk))
                                 .ToList();

                foreach (var chunk in chunks)
                {
                    // Further split large chunks if necessary
                    if (chunk.Length > 500)
                    {
                        var subChunks = SplitByWordLimit(chunk, 500);
                        foreach (var subChunk in subChunks)
                        {
                            var responseUrl = await GenerateAudioForChunkAsync(subChunk);
                            if (!string.IsNullOrEmpty(responseUrl))
                            {
                                audioUrls.Add(responseUrl);
                            }
                        }
                    }
                    else
                    {
                        var responseUrl = await GenerateAudioForChunkAsync(chunk);
                        if (!string.IsNullOrEmpty(responseUrl))
                        {
                            audioUrls.Add(responseUrl);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating audio for chunks: {ex.Message}");
            }

            return audioUrls;
        }

        private async Task<string> GenerateAudioForChunkAsync(string chunk)
        {

            var payload = new
            {
                text = chunk,
                output_dir = _outputDirectory
            };

            var outputPath = await PostToAudioApiAsync(payload);

            if (!string.IsNullOrEmpty(outputPath))
            {
                string fileName = outputPath.Replace(_outputDirectory, "");
                fileName= fileName.TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                string returnUrl = _baseUrl + fileName;
                _logger.LogInformation($"Audio generated successfully: {returnUrl}");
                return returnUrl;
            }
            return string.Empty;
        }

        private async Task<string?> PostToAudioApiAsync(object payload)
        {
            try
            {
                using var client = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(5) // Set the timeout to 5 seconds
                };
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                var response = await client.PostAsync(_apiEndpoint, content);

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadAsStringAsync();
                    var responseData = JsonSerializer.Deserialize<Dictionary<string, string>>(result);

                    if (responseData != null && responseData.TryGetValue("output_path", out string? outputPath))
                    {
                        return outputPath; // Return actual output path
                    }
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    _logger.LogError($"Audio API request failed: {error}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error sending request to audio API: {ex.Message}");
            }

            return string.Empty;
        }
        private List<string> SplitByWordLimit(string text, int maxLength)
        {
            var words = text.Split(' ');
            var result = new List<string>();
            var currentChunk = new List<string>();

            foreach (var word in words)
            {
                if (currentChunk.Sum(w => w.Length) + word.Length + currentChunk.Count <= maxLength)
                {
                    currentChunk.Add(word);
                }
                else
                {
                    result.Add(string.Join(" ", currentChunk));
                    currentChunk.Clear();
                    currentChunk.Add(word);
                }
            }

            if (currentChunk.Count > 0)
            {
                result.Add(string.Join(" ", currentChunk));
            }

            return result;
        }

    }
}

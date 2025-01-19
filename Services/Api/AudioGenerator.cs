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

namespace NetworkMonitor.LLM.Services
{
    public class AudioGenerator
    {
        private static readonly string _apiEndpoint = "https://devtranscribe.freenetworkmonitor.click/generate_audio";
        private static  string _baseUrl = "https://freenetworkmonitor.click/output_audio/";
        private static readonly string _outputDirectory = "/home/mahadeva/code/securefiles/dev/output_audio"; // Centralized property

        public static async Task<string> AudioForResponse(string text, ILogger logger, string frontendUrl)
        {
            try
            {
                if (!string.IsNullOrEmpty(frontendUrl)){
                    _baseUrl=frontendUrl+"/output_audio/";
                }
                var payload = new
                {
                    text,
                    output_dir = _outputDirectory
                };

                var outputPath = await PostToAudioApiAsync(payload, logger);

                if (!string.IsNullOrEmpty(outputPath))
                {
                    string fileName = outputPath.Replace(_outputDirectory, "").TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                    string returnUrl = _baseUrl + fileName;
                    logger.LogInformation($"Audio generated successfully: {returnUrl}");
                    return returnUrl;
                }

                logger.LogError("Audio generation failed for single response.");
                return string.Empty;
            }
            catch (Exception ex)
            {
                logger.LogError($"Error generating audio: {ex.Message}");
                return string.Empty;
            }
        }

        public static List<string> GetChunksFromText(string text, int maxLength = 500)
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

        public static async Task<List<string>> AudioForResponseChunks(string text, ILogger logger)
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
                            var responseUrl = await GenerateAudioForChunkAsync(subChunk, logger);
                            if (!string.IsNullOrEmpty(responseUrl))
                            {
                                audioUrls.Add(responseUrl);
                            }
                        }
                    }
                    else
                    {
                        var responseUrl = await GenerateAudioForChunkAsync(chunk, logger);
                        if (!string.IsNullOrEmpty(responseUrl))
                        {
                            audioUrls.Add(responseUrl);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError($"Error generating audio for chunks: {ex.Message}");
            }

            return audioUrls;
        }

        private static async Task<string> GenerateAudioForChunkAsync(string chunk, ILogger logger)
        {

            var payload = new
            {
                text = chunk,
                output_dir = _outputDirectory
            };

            var outputPath = await PostToAudioApiAsync(payload, logger);

            if (!string.IsNullOrEmpty(outputPath))
            {
                string fileName = outputPath.Replace(_outputDirectory, "").TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                string returnUrl = _baseUrl + fileName;
                logger.LogInformation($"Audio generated successfully: {returnUrl}");
                return returnUrl;
            }
            return string.Empty;
        }

        private static async Task<string> PostToAudioApiAsync(object payload, ILogger logger)
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

                    if (responseData != null && responseData.TryGetValue("output_path", out var outputPath))
                    {
                        return outputPath; // Return actual output path
                    }
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    logger.LogError($"Audio API request failed: {error}");
                }
            }
            catch (Exception ex)
            {
                logger.LogError($"Error sending request to audio API: {ex.Message}");
            }

            return string.Empty;
        }
        private static List<string> SplitByWordLimit(string text, int maxLength)
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

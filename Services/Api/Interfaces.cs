using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using NetworkMonitor.Objects;
using System.Runtime.CompilerServices;

namespace NetworkMonitor.LLM.Services
{
    public interface IAudioGenerator
    {
        /// <summary>
        /// Generates audio for the given text and returns the URL of the audio file.
        /// </summary>
        /// <param name="text">The text to generate audio for.</param>
        /// <returns>A task representing the asynchronous operation, containing the URL of the generated audio file.</returns>
        Task<string> AudioForResponse(string text);
        Task<List<string>> AudioForResponseChunksOrderedFastFirst(string text);
        IAsyncEnumerable<string> StreamAudioInOrder(
      string text,
      CancellationToken ct = default);

        /// <summary>
        /// Splits the given text into chunks based on a maximum length.
        /// </summary>
        /// <param name="text">The text to split.</param>
        /// <param name="maxLength">The maximum length of each chunk.</param>
        /// <returns>A list of text chunks.</returns>
        List<string> GetChunksFromText(string text, int maxLength = 500);

        /// <summary>
        /// Generates audio for each chunk of the given text and returns a list of URLs for the audio files.
        /// </summary>
        /// <param name="text">The text to generate audio for.</param>
        /// <returns>A task representing the asynchronous operation, containing a list of URLs for the generated audio files.</returns>
        Task<List<string>> AudioForResponseChunks(string text);
    }
}

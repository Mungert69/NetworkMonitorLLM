using System;
using System.Threading.Tasks;

namespace NetworkMonitor.LLM.Services.Cache;

public interface IRemoteCacheService
{
    /// <summary>
    /// Checks if a context file exists in the remote cache
    /// </summary>
    /// <param name="fileName">The filename of the context file</param>
    /// <param name="fileHash">The SHA256 hash of the prompt content</param>
    /// <returns>True if the file exists in remote cache, false otherwise</returns>
    Task<bool> HasContextFileAsync(string fileName, string fileHash);

    /// <summary>
    /// Downloads a context file from the remote cache
    /// </summary>
    /// <param name="fileName">The filename of the context file</param>
    /// <param name="fileHash">The SHA256 hash of the prompt content</param>
    /// <returns>Byte array containing the context file data</returns>
    Task<byte[]> DownloadContextFileAsync(string fileName, string fileHash);

    /// <summary>
    /// Uploads a context file to the remote cache
    /// </summary>
    /// <param name="fileName">The filename of the context file</param>
    /// <param name="fileHash">The SHA256 hash of the prompt content</param>
    /// <param name="fileData">The context file data as byte array</param>
    Task UploadContextFileAsync(string fileName, string fileHash, byte[] fileData);
}
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Utils;
namespace NetworkMonitor.LLM.Services;
public class AudioGenerator{

public static async Task<string> AudioForResponse(string text, ILogger logger)
{
    try
    {
        // Path to the Python script and environment activation
        string pythonExecutable = "/home/mahadeva/code/models/env/bin/python3";
        string scriptPath = "/home/mahadeva/code/models/kokoro/text_2_speech.py";
        string workingDirectory = "/home/mahadeva/code/models/kokoro";
        string guid=Guid.NewGuid().ToString();
        string audioFilePath = $"/home/mahadeva/code/FreeNetworkMonitor/public/output_audio/output_audio_am_adam_{guid}.wav";
         string returnFilePath = $"https://devwww.freenetworkmonitor.click/output_audio/output_audio_am_adam_{guid}.wav";

        // Run the Python script
        var processStartInfo = new ProcessStartInfo
        {
            FileName = pythonExecutable,
            Arguments = $"{scriptPath} --text \"{text}\" --output \"{audioFilePath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory 
        };

        using var process = new Process
        {
            StartInfo = processStartInfo
        };

        process.Start();

        string output = await process.StandardOutput.ReadToEndAsync();
        string error = await process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        if (process.ExitCode == 0)
        {
            logger.LogInformation($"Audio generated successfully: {returnFilePath}");
            return returnFilePath;
        }
        else
        {
            logger.LogError($"Audio generation failed. Error: {error}");
            return string.Empty;
        }
    }
    catch (Exception ex)
    {
        logger.LogError($"Error generating audio: {ex.Message}");
        return string.Empty;
    }
}


}

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NetworkMonitor.Objects;
namespace NetworkMonitor.LLM.Services;
public static class ProcessKiller
{
    public static void ForceKillProcess(ProcessWrapper process)
    {
        if (process == null || process.HasExited)
        {
            return; // Process is already terminated
        }

        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                KillProcessOnWindows(process.Id);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                KillProcessOnUnix(process.Id);
            }
            else
            {
                // Fallback to .NET Kill if OS is not specifically handled
                process.Kill();
                process.Dispose();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to kill process with PID={process.Id}: {ex.Message}");
        }
    }

    private static void KillProcessOnWindows(int processId)
    {
        try
        {
            // Use taskkill command to forcibly terminate the process
            var startInfo = new ProcessStartInfo
            {
                FileName = "taskkill",
                Arguments = $"/PID {processId} /F", // /F means force termination
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var taskKillProcess = Process.Start(startInfo);
            if (taskKillProcess==null) 
             {
                Console.WriteLine($"taskkill failed for PID={processId}. Process.Start(startInfo) is null");
                return;
            }
            taskKillProcess.WaitForExit();

            if (taskKillProcess.ExitCode != 0)
            {
                Console.WriteLine($"taskkill failed for PID={processId}. ExitCode={taskKillProcess.ExitCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to execute taskkill for PID={processId}: {ex.Message}");
        }
    }

    private static void KillProcessOnUnix(int processId)
    {
        try
        {
            // Use kill command to send SIGKILL (signal 9) to the process
            var startInfo = new ProcessStartInfo
            {
                FileName = "kill",
                Arguments = $"-9 {processId}", // -9 sends the SIGKILL signal
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var killProcess = Process.Start(startInfo);
             if (killProcess==null) 
             {
                Console.WriteLine($"killProcess failed for PID={processId}. Process.Start(startInfo) is null");
                return;
            }
            killProcess.WaitForExit();

            if (killProcess.ExitCode != 0)
            {
                Console.WriteLine($"kill -9 failed for PID={processId}. ExitCode={killProcess.ExitCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to execute kill -9 for PID={processId}: {ex.Message}");
        }
    }
}

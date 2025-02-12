using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public interface ICpuUsageMonitor
{
    /// <summary>
    /// Gets the current rolling average CPU usage for the entire system.
    /// </summary>
    float GetCurrentAverageCpuUsage();

    /// <summary>
    /// Recommends the number of CPUs to use based on the current system load.
    /// </summary>
    /// <param name="maxCpu">The maximum number of CPUs available for scaling.</param>
    /// <param name="targetCpuUsage">The target CPU usage percentage (default is 80%).</param>
    /// <returns>The recommended number of CPUs to use.</returns>
    int RecommendCpuCount(int maxCpu, float targetCpuUsage = 80f);
}

public class CpuUsageMonitor : ICpuUsageMonitor, IHostedService, IDisposable
{
    private readonly ILogger<CpuUsageMonitor> _logger;
    private readonly int _sampleIntervalMs = 1000; // Sample every 1 second
    private readonly int _rollingAverageDurationMs = 60000; // Rolling average over 60 seconds
    private readonly Queue<float> _cpuUsageSamples = new Queue<float>();
    private Timer _timer;
    private float _currentAverageCpuUsage;

    public CpuUsageMonitor(ILogger<CpuUsageMonitor> logger)
    {
        _logger = logger;
    }

    public float GetCurrentAverageCpuUsage()
    {
        return _currentAverageCpuUsage;
    }

    public int RecommendCpuCount(int maxCpu, float targetCpuUsage = 66f)
    {
        if (_currentAverageCpuUsage <= 0) return 1; // Default to 1 if no valid data

        int recommendedCpuCount = (int)Math.Round((targetCpuUsage / _currentAverageCpuUsage) * Environment.ProcessorCount);
        recommendedCpuCount = Math.Clamp(recommendedCpuCount, 1, maxCpu);

        _logger.LogInformation($"Current CPU Usage: {_currentAverageCpuUsage:F2}%, Recommended CPU Count: {recommendedCpuCount}");
        return recommendedCpuCount;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("CPU Usage Monitor started.");
        _timer = new Timer(SampleCpuUsage, null, 0, _sampleIntervalMs);
        return Task.CompletedTask;
    }

    private void SampleCpuUsage(object state)
    {
        float cpuUsage = GetTotalSystemCpuUsage();
        _cpuUsageSamples.Enqueue(cpuUsage);

        // Remove old samples that exceed the rolling average window
        while (_cpuUsageSamples.Count > _rollingAverageDurationMs / _sampleIntervalMs)
        {
            _cpuUsageSamples.Dequeue();
        }

        // Calculate rolling average
        _currentAverageCpuUsage = _cpuUsageSamples.Count > 0 ? _cpuUsageSamples.Average() : 0;
        _logger.LogDebug($"Sampled CPU Usage: {cpuUsage:F2}%, Rolling Average: {_currentAverageCpuUsage:F2}%");
    }

    private float GetTotalSystemCpuUsage()
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return GetWindowsCpuUsage();
            else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                return GetLinuxMacCpuUsage();
            else
                throw new PlatformNotSupportedException("Unsupported operating system.");
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error getting CPU usage: {ex.Message}");
            return 0;
        }
    }

    private float GetWindowsCpuUsage()
    {
        using (var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total"))
        {
            cpuCounter.NextValue(); // First call gives 0, discard it
            Thread.Sleep(500); // Wait before fetching valid data
            return cpuCounter.NextValue();
        }
    }

  private float GetLinuxMacCpuUsage()
{
    try
    {
        // Read first snapshot
        var firstSample = ReadCpuStats();
        if (firstSample == null) return 0;

        Thread.Sleep(500); // Short delay before second reading

        // Read second snapshot
        var secondSample = ReadCpuStats();
        if (secondSample == null) return 0;

        // Calculate differences
        long totalDiff = secondSample.Total - firstSample.Total;
        long idleDiff = secondSample.Idle - firstSample.Idle;

        return totalDiff == 0 ? 0 : (100f * (totalDiff - idleDiff) / totalDiff);
    }
    catch (Exception ex)
    {
        _logger.LogError($"Error reading CPU usage: {ex.Message}");
        return 0;
    }
}

private CpuTimes ReadCpuStats()
{
    try
    {
        var lines = File.ReadAllLines("/proc/stat");
        var cpuLine = lines.FirstOrDefault(line => line.StartsWith("cpu "));
        if (cpuLine == null) return null;

        var values = cpuLine.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1)
                            .Select(v => long.TryParse(v, out var parsed) ? parsed : 0)
                            .ToArray();

        if (values.Length < 5) return null; // Not enough fields to calculate CPU usage

        long user = values[0];
        long nice = values[1];
        long system = values[2];
        long idle = values[3];
        long iowait = values.Length > 4 ? values[4] : 0; // Some systems may not have iowait

        long irq = values.Length > 5 ? values[5] : 0;
        long softirq = values.Length > 6 ? values[6] : 0;
        long steal = values.Length > 7 ? values[7] : 0;

        long total = user + nice + system + idle + iowait + irq + softirq + steal;

        return new CpuTimes { Total = total, Idle = idle + iowait }; // Including iowait in Idle
    }
    catch (Exception ex)
    {
        _logger.LogError($"Error parsing /proc/stat: {ex.Message}");
        return null;
    }
}

private class CpuTimes
{
    public long Total { get; set; }
    public long Idle { get; set; }
}

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("CPU Usage Monitor stopped.");
        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}

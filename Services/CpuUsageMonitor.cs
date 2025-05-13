using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;

public interface ICpuUsageMonitor
{
    float GetCurrentAverageCpuUsage();
    int RecommendCpuCount(int maxCpu, float targetCpuUsage = 50f);
    bool IsMemoryTooLow(float minFreeMemoryPercentage = 50f);
    bool IsSwapTooHigh(float maxSwapUsagePercentage = 50f);
    bool IsMemoryAvailable(int memoryInMB);
}

public class CpuUsageMonitor : ICpuUsageMonitor, IHostedService, IDisposable
{
    private readonly ILogger<CpuUsageMonitor> _logger;
    private readonly int _sampleIntervalMs = 1000;
    private readonly int _rollingAverageDurationMs = 60000;
    private readonly Queue<float> _cpuUsageSamples = new();
    private Timer? _timer;
    private float _currentAverageCpuUsage;

    public CpuUsageMonitor(ILogger<CpuUsageMonitor> logger)
    {
        _logger = logger;
    }

    public float GetCurrentAverageCpuUsage() => _currentAverageCpuUsage;

    public int RecommendCpuCount(int maxCpu, float targetCpuUsage = 50f)
    {
        if (_currentAverageCpuUsage <= 5)
            return maxCpu;

        float usageRatio = _currentAverageCpuUsage / targetCpuUsage;
        int recommended;

        if (usageRatio > 1)
            recommended = (int)Math.Max(1, maxCpu / (usageRatio * 2.0f));
        else
            recommended = (int)Math.Min(maxCpu, maxCpu * (0.8f + (1 - usageRatio) * 0.4f));

        recommended = Math.Clamp(recommended, 1, maxCpu);

        _logger.LogInformation(
            $"CPU Avg: {_currentAverageCpuUsage:F1}%, Target: {targetCpuUsage:F1}%, " +
            $"Ratio: {usageRatio:F2}, Recommended CPUs: {recommended}/{maxCpu}"
        );

        return recommended;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting CPU monitor...");
        _timer = new Timer(SampleCpuUsage, null, 0, _sampleIntervalMs);
        return Task.CompletedTask;
    }

    private async void SampleCpuUsage(object? state)
    {
        float usage = await GetTotalSystemCpuUsage();
        _cpuUsageSamples.Enqueue(usage);

        while (_cpuUsageSamples.Count > _rollingAverageDurationMs / _sampleIntervalMs)
            _cpuUsageSamples.Dequeue();

        _currentAverageCpuUsage = _cpuUsageSamples.Count > 0
            ? _cpuUsageSamples.Average()
            : 0;
    }

    private async Task<float> GetTotalSystemCpuUsage()
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return await GetWindowsCpuUsage();
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                return await GetLinuxMacCpuUsage();

            throw new PlatformNotSupportedException();
        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to read CPU usage: {ex.Message}");
            return 0;
        }
    }

    private async Task<float> GetWindowsCpuUsage()
    {
#pragma warning disable CA1416
        using var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
        cpuCounter.NextValue();
        await Task.Delay(500);
        return cpuCounter.NextValue();
#pragma warning restore CA1416
    }

    private async Task<float> GetLinuxMacCpuUsage()
    {
        var first = await ReadCpuStats();
        if (first == null) return 0;

        await Task.Delay(500);
        var second = await ReadCpuStats();
        if (second == null) return 0;

        long totalDelta = second.Total - first.Total;
        long idleDelta = second.Idle - first.Idle;

        return totalDelta == 0 ? 0 : (100f * (totalDelta - idleDelta) / totalDelta);
    }

    private async Task<CpuTimes?> ReadCpuStats()
    {
        try
        {
            var lines = await File.ReadAllLinesAsync("/proc/stat");
            var cpuLine = lines.FirstOrDefault(line => line.StartsWith("cpu "));
            if (cpuLine == null) return null;

            var parts = cpuLine.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1)
                .Select(p => long.TryParse(p, out var v) ? v : 0)
                .ToArray();

            if (parts.Length < 4) return null;

            long user = parts[0], nice = parts[1], system = parts[2],
                 idle = parts[3], iowait = parts.Length > 4 ? parts[4] : 0,
                 irq = parts.Length > 5 ? parts[5] : 0, softirq = parts.Length > 6 ? parts[6] : 0,
                 steal = parts.Length > 7 ? parts[7] : 0;

            long total = user + nice + system + idle + iowait + irq + softirq + steal;
            return new CpuTimes { Total = total, Idle = idle + iowait };
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error parsing /proc/stat: {ex.Message}");
            return null;
        }
    }

    private record CpuTimes
    {
        public long Total { get; init; }
        public long Idle { get; init; }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping CPU monitor...");
        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    public bool IsSwapTooHigh(float maxSwapUsagePercentage = 50f)
    {
        float percent = GetSwapUsagePercentage();
        bool tooHigh = percent > maxSwapUsagePercentage;
        _logger.LogInformation($"Swap Usage: {percent:F1}%, Safe: {!tooHigh}");
        return tooHigh;
    }

    private float GetSwapUsagePercentage()
    {
        if (OperatingSystem.IsWindows())
            return 0; // not implemented
        return GetLinuxMacSwapUsage();
    }

    private float GetLinuxMacSwapUsage()
    {
        try
        {
            var lines = File.ReadAllLines("/proc/meminfo");
            long swapTotal = ParseMemValue(lines, "SwapTotal");
            long swapFree = ParseMemValue(lines, "SwapFree");

            return swapTotal == 0 ? 0 : (float)(swapTotal - swapFree) / swapTotal * 100;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Swap read error: {ex.Message}");
            return 0;
        }
    }

    public bool IsMemoryTooLow(float minFreeMemoryPercentage = 50f)
    {
        float percent = GetFreeMemoryPercentage();
        bool tooLow = percent < minFreeMemoryPercentage;
        _logger.LogInformation($"Free Memory: {percent:F1}%, Safe: {!tooLow}");
        return tooLow;
    }

    private float GetFreeMemoryPercentage()
    {
        if (OperatingSystem.IsWindows())
            return GetWindowsMemoryUsage();
        return GetLinuxMacMemoryUsage();
    }

    private float GetWindowsMemoryUsage()
    {
        var info = GC.GetGCMemoryInfo();
        ulong total = (ulong)info.TotalAvailableMemoryBytes;
        ulong used = (ulong)info.HeapSizeBytes;
        ulong free = total - used;
        return total == 0 ? 100 : (float)free / total * 100;
    }

    private float GetLinuxMacMemoryUsage()
    {
        try
        {
            var lines = File.ReadAllLines("/proc/meminfo");
            long total = ParseMemValue(lines, "MemTotal");
            long free = ParseMemValue(lines, "MemFree");
            long buffers = ParseMemValue(lines, "Buffers");
            long cached = ParseMemValue(lines, "Cached");

            long available = free + buffers + cached;
            return total == 0 ? 100 : (float)available / total * 100;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Memory read error: {ex.Message}");
            return 100;
        }
    }

    private long ParseMemValue(string[] lines, string key)
    {
        var line = lines.FirstOrDefault(l => l.StartsWith(key));
        return line == null ? 0 : long.Parse(Regex.Match(line, @"\d+").Value);
    }

    public bool IsMemoryAvailable(int memoryInMB)
    {
        try
        {
            var lines = File.ReadAllLines("/proc/meminfo");
            long avail = ParseMemValue(lines, "MemAvailable");
            long swap = ParseMemValue(lines, "SwapFree");
            long total = avail + swap;
            long need = memoryInMB * 1024L; // memoryInMB in kB

            _logger.LogInformation($"Memory needed: {need} kB, available: {total} kB");
            return total > need;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Memory availability check failed: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}

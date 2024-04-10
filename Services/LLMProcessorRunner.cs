using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
namespace NetworkMonitor.LLM.Services;
// LLMProcessRunner.cs
public interface ILLMProcessRunner
{
    Task StartProcess(string sessionId, ProcessWrapper? testProcess = null);
    Task SendInputAndGetResponse(string sessionId, string userInput, bool isFunctionCallResponse);
    void RemoveProcess(string sessionId);
}
public class LLMProcessRunner : ILLMProcessRunner
{
    //private ProcessWrapper _llamaProcess;
    private readonly ConcurrentDictionary<string, ProcessWrapper> _processes = new ConcurrentDictionary<string, ProcessWrapper>();
    private readonly ConcurrentDictionary<string, TokenBroadcaster> _tokenBroadcasters = new ConcurrentDictionary<string, TokenBroadcaster>();

    private ILogger _logger;
    private ILLMResponseProcessor _responseProcessor;
    private MLParams _mlParams;
    private Timer _idleCheckTimer;
    private readonly SemaphoreSlim _inputStreamSemaphore = new SemaphoreSlim(1, 1);
    public LLMProcessRunner(ILogger<LLMProcessRunner> logger, ILLMResponseProcessor responseProcessor, ISystemParamsHelper systemParamsHelper)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _mlParams = systemParamsHelper.GetMLParams();
        _idleCheckTimer = new Timer(async _ => await CheckAndTerminateIdleProcesses(), null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));

    }

    private async Task CheckAndTerminateIdleProcesses()
    {
        var idleDuration = TimeSpan.FromMinutes(30);
        var currentDateTime = DateTime.UtcNow;
        var sessionsToTerminate = _processes.Where(p => currentDateTime - p.Value.LastActivity > idleDuration).Select(p => p.Key).ToList();

        foreach (var sessionId in sessionsToTerminate)
        {
            RemoveProcess(sessionId);
            await _responseProcessor.ProcessEnd(new LLMServiceObj() { SessionId = sessionId, LlmMessage = "Close: Session has timeout. Refresh page to start session again." });
             _logger.LogInformation($" LLM Service : terminated session {sessionId}");
       
        }
    }

    public void SetStartInfo(ProcessStartInfo startInfo, MLParams mlParams)
    {
        startInfo.FileName = $"{mlParams.LlmModelPath}llama.cpp/build/bin/main";
        startInfo.Arguments = $"-c 4000 -n 4000 -m {mlParams.LlmModelPath + mlParams.LlmModelFileName}  --prompt-cache {mlParams.LlmModelPath+mlParams.LlmContextFileName} --prompt-cache-ro  -f {mlParams.LlmModelPath+mlParams.LlmSystemPrompt}  -ins -r \"<|stop|>\" --keep -1 --temp 0 -t 8";
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardInput = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.CreateNoWindow = true;
    }
    public async Task StartProcess(string sessionId, ProcessWrapper? testProcess = null)
    {
        if (_processes.ContainsKey(sessionId))
            throw new Exception("Process already running for this session");
        _logger.LogInformation($" LLM Service : Start Process for sessionsId {sessionId}");
        ProcessWrapper process;
        if (testProcess == null)
        {
            process = new ProcessWrapper();
            SetStartInfo(process.StartInfo, _mlParams);
        }
        else
        {
            process = testProcess;
        }
        process.Start();
        await WaitForReadySignal(process);
        _processes[sessionId] = process;
        _logger.LogInformation($"LLM process started for session {sessionId}");
    }
    public void RemoveProcess(string sessionId)
    {
        if (!_processes.TryGetValue(sessionId, out var process))
            throw new Exception("Process is not running for this session");
        _logger.LogInformation($" LLM Service : Remove Process for sessionsId {sessionId}");
        try
        {
            if (!process.HasExited)
            {
                process.Kill();
            }
        }
        finally
        {
            // Always dispose of the process object
            process.Dispose();
        }
        // _processes.TryRemove(sessionId);

        _processes.TryRemove(sessionId, out _);

        _logger.LogInformation($"LLM process removed for session {sessionId}");
    }
    private async Task WaitForReadySignal(ProcessWrapper process)
    {
        bool isReady = false;
        string line;
        //await Task.Delay(10000);
        var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.CancelAfter(TimeSpan.FromMinutes(1)); // Timeout after one minute
        while (!cancellationTokenSource.IsCancellationRequested)
        {
            line = await process.StandardOutput.ReadLineAsync();
            if (line.StartsWith("<|content|>A chat between"))
            {
                isReady = true;
                break;
            }
        }
        if (!isReady)
        {
            throw new Exception("LLM process failed to indicate readiness");
        }
        _logger.LogInformation($" LLMService Process Started ");
    }
    public async Task SendInputAndGetResponse(string sessionId, string userInput, bool isFunctionCallResponse)
    {
        _logger.LogInformation($"  LLMService : SendInputAndGetResponse() :");

        if (!_processes.TryGetValue(sessionId, out var process))
            throw new Exception("No process found for the given session");

        if (process == null || process.HasExited)
        {
            throw new InvalidOperationException("LLM process is not running");
        }

        TokenBroadcaster tokenBroadcaster;
        if (_tokenBroadcasters.TryGetValue(sessionId, out tokenBroadcaster))
        {
            await tokenBroadcaster.ReInit(sessionId);
        }
        else
        {
            tokenBroadcaster = new TokenBroadcaster(_responseProcessor, _logger);
        }
        userInput = "<|from|>user<|recipient|>all<|content|>" + userInput;
        await process.StandardInput.WriteLineAsync(userInput);
        await process.StandardInput.FlushAsync();
        _logger.LogInformation($" ProcessLLMOutput(user input) -> {userInput}");


        await tokenBroadcaster.BroadcastAsync(process, sessionId, userInput, isFunctionCallResponse);

    }
}


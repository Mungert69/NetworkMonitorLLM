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
using System.Security.Cryptography.X509Certificates;
namespace NetworkMonitor.LLM.Services;
// LLMProcessRunner.cs

public class LLMProcessRunner : ILLMRunner
{
    //private ProcessWrapper _llamaProcess;
    private readonly ConcurrentDictionary<string, ProcessWrapper> _processes = new ConcurrentDictionary<string, ProcessWrapper>();
    private readonly ConcurrentDictionary<string, TokenBroadcaster> _tokenBroadcasters = new ConcurrentDictionary<string, TokenBroadcaster>();
    private bool _sendOutput = false;
    private ILogger _logger;
    private ILLMResponseProcessor _responseProcessor;
    private MLParams _mlParams;
    private Timer _idleCheckTimer;
    private SemaphoreSlim _processRunnerSemaphore;
    public LLMProcessRunner(ILogger<LLMProcessRunner> logger, ILLMResponseProcessor responseProcessor, ISystemParamsHelper systemParamsHelper, SemaphoreSlim processRunnerSemaphore)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _mlParams = systemParamsHelper.GetMLParams();
        _processRunnerSemaphore = processRunnerSemaphore;
        _idleCheckTimer = new Timer(async _ => await CheckAndTerminateIdleProcesses(), null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));

    }

    private async Task CheckAndTerminateIdleProcesses()
    {
        var idleDuration = TimeSpan.FromMinutes(30);
        var currentDateTime = DateTime.UtcNow;
        var sessionsToTerminate = _processes.Where(p => currentDateTime - p.Value.LastActivity > idleDuration).Select(p => p.Key).ToList();

        foreach (var sessionId in sessionsToTerminate)
        {
            await RemoveProcess(sessionId);
            await _responseProcessor.ProcessEnd(new LLMServiceObj() { SessionId = sessionId, LlmMessage = "Close: Session has timeout. Refresh page to start session again." });
            _logger.LogInformation($" LLM Service : terminated session {sessionId}");

        }
    }

    public void SetStartInfo(ProcessStartInfo startInfo, MLParams mlParams)
    {
        startInfo.FileName = $"{mlParams.LlmModelPath}llama.cpp/main";
        startInfo.Arguments = $"-c 2000 -n 6000 -b 224 -m {mlParams.LlmModelPath + mlParams.LlmModelFileName}  --prompt-cache {mlParams.LlmModelPath + mlParams.LlmContextFileName} --prompt-cache-ro  -f {mlParams.LlmModelPath + mlParams.LlmSystemPrompt}  -ins -r \"<|stop|>\" --keep -1 --temp 0 -t {mlParams.LlmThreads}";
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardInput = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.CreateNoWindow = true;
    }
    public async Task StartProcess(string sessionId, DateTime currentTime)
    {

        await _processRunnerSemaphore.WaitAsync(); // Wait to enter the semaphore
        try
        {
            if (_processes.ContainsKey(sessionId))
                throw new Exception("Process already running for this session");
            _logger.LogInformation($" LLM Service : Start Process for sessionsId {sessionId}");
            ProcessWrapper process;

            process = new ProcessWrapper();
            SetStartInfo(process.StartInfo, _mlParams);

            process.Start();
            await WaitForReadySignal(process);
            _processes[sessionId] = process;
        }
        catch
        {
            throw;
        }
        finally
        {
            _processRunnerSemaphore.Release(); // Release the semaphore
        }
        string userInput = $"<|from|>get_time<|content|>{currentTime.ToString()}";
        var serviceObj = new LLMServiceObj() { SessionId = sessionId, UserInput = userInput, IsFunctionCallResponse = false };
        _sendOutput = false;
        await SendInputAndGetResponse(serviceObj);
        _logger.LogInformation($"LLM process started for session {sessionId}");
        _sendOutput = true;

    }
    public async Task RemoveProcess(string sessionId)
    {
        if (!_processes.TryGetValue(sessionId, out var process))
            throw new Exception("Process is not running for this session");

        _logger.LogInformation($" LLM Service : Remove Process for sessionsId {sessionId}");

        try
        {
            if (process != null && !process.HasExited)
            {
                process.Kill();
            }
        }
        finally
        {
            if (process != null)
            {
                process.Dispose();
                _processes.TryRemove(sessionId, out _);
            }
        }
        _logger.LogInformation($"LLM process removed for session {sessionId}");
    }
    private async Task WaitForReadySignal(ProcessWrapper process)
    {
        bool isReady = false;
        string line;
        //await Task.Delay(10000);
        var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.CancelAfter(TimeSpan.FromSeconds(30)); // Timeout after one minute
        while (!cancellationTokenSource.IsCancellationRequested)
        {
            line = await process.StandardOutput.ReadLineAsync();
            if (line.StartsWith("<|content|>A chat"))
            {
                isReady = true;
                break;
            }
        }
        if (!isReady)
        {
            throw new Exception(" Timeout waiting for FreeLLM process to start");
        }
        _logger.LogInformation($" LLMService Process Started ");
    }

    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
        await _processRunnerSemaphore.WaitAsync();
        try
        {
            _logger.LogInformation($"  LLMService : SendInputAndGetResponse() :");

            if (!_processes.TryGetValue(serviceObj.SessionId, out var process))
                throw new Exception("No process found for the given session");

            if (process == null || process.HasExited)
            {
                throw new InvalidOperationException("LLM process is not running");
            }

            TokenBroadcaster tokenBroadcaster;
            if (_tokenBroadcasters.TryGetValue(serviceObj.SessionId, out tokenBroadcaster))
            {
                await tokenBroadcaster.ReInit(serviceObj.SessionId);
            }
            else
            {
                tokenBroadcaster = new TokenBroadcaster(_responseProcessor, _logger);
            }
            string userInput = serviceObj.UserInput;
            if (!serviceObj.IsFunctionCallResponse && _sendOutput) userInput = "<|from|>user<|content|>" + userInput;
            await process.StandardInput.WriteLineAsync(userInput);
            await process.StandardInput.FlushAsync();
            _logger.LogInformation($" ProcessLLMOutput(user input) -> {userInput}");


            await tokenBroadcaster.BroadcastAsync(process, serviceObj.SessionId, userInput, serviceObj.IsFunctionCallResponse, _sendOutput);
        }
        catch
        {
            throw;
        }
        finally
        {
            _processRunnerSemaphore.Release(); // Release the semaphore

        }
    }
}


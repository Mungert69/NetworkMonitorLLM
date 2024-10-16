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
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils.Helpers;
using System.Security.Cryptography.X509Certificates;
namespace NetworkMonitor.LLM.Services;
// LLMProcessRunner.cs
public class LLMProcessRunner : ILLMRunner
{
    //private ProcessWrapper _llamaProcess;
    private readonly ConcurrentDictionary<string, ProcessWrapper> _processes = new ConcurrentDictionary<string, ProcessWrapper>();
    private readonly ConcurrentDictionary<string, ITokenBroadcaster> _tokenBroadcasters = new ConcurrentDictionary<string, ITokenBroadcaster>();
    private bool _sendOutput = false;
    private ILogger _logger;
    private ILLMResponseProcessor _responseProcessor;
    private MLParams _mlParams;
    private Timer _idleCheckTimer;
    private SemaphoreSlim _processRunnerSemaphore;

    public string Type { get => "FreeLLM"; }
    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private string _serviceID;
    private LLMServiceObj _startServiceoObj;

    public bool IsStateReady { get => _isStateReady; }
    public bool IsStateStarting { get => _isStateStarting; }
    public bool IsStateFailed { get => _isStateFailed; }

    public LLMProcessRunner(ILogger<LLMProcessRunner> logger, ILLMResponseProcessor responseProcessor, ISystemParamsHelper systemParamsHelper, LLMServiceObj startServiceObj, SemaphoreSlim processRunnerSemaphore)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _startServiceoObj = startServiceObj;
        _mlParams = systemParamsHelper.GetMLParams();
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _processRunnerSemaphore = processRunnerSemaphore;
        _idleCheckTimer = new Timer(async _ => await CheckAndTerminateIdleProcesses(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }
    private async Task CheckAndTerminateIdleProcesses()
    {
        var idleDuration = TimeSpan.FromMinutes(_mlParams.LlmSessionIdleTimeout);
        var currentDateTime = DateTime.UtcNow;
        var sessionsToTerminate = _processes.Where(p => currentDateTime - p.Value.LastActivity > idleDuration).Select(p => p.Key).ToList();
        foreach (var sessionId in sessionsToTerminate)
        {
            await RemoveProcess(sessionId);
            await _responseProcessor.ProcessEnd(new LLMServiceObj() { SessionId = sessionId, LlmMessage = "Close: Session has timed out. Reload Assistant to start session again." });
            _logger.LogInformation($" LLM Service : terminated session {sessionId}");
        }
    }
    public void SetStartInfo(ProcessStartInfo startInfo, MLParams mlParams)
    {
        string promptPrefix = "";
        string extraReversePrompt = "";
        // if (!mlParams.LlmIsfunc_2.4) promptPrefix = " --in-prefix \"<|user|>\" ";
        //if (mlParams.LlmVersion == "func_3.1" || mlParams.LlmVersion == "func_3.2") extraReversePrompt = " -r \"<|eom_id|>\" ";


        if (_startServiceoObj.UserInfo.AccountType == null)
        {
            _startServiceoObj.UserInfo.AccountType = "Free";
            _logger.LogError($" Error : User {_startServiceoObj.UserInfo.UserID} account type is null setting to Free as default");
        }

        string permissionSuffix = "";
        // Old way of doing permission is to load different context. new way is to let the api deal with it
        /*string permissionSuffix = "_free";
        if (!_mlParams.StartOnlyOneFreeLLM) permissionSuffix = AccountTypeFactory.GetPermissionSuffix(
            _startServiceoObj.UserInfo.AccountType,
            _startServiceoObj.LlmSessionStartName,
            _startServiceoObj.LlmChainStartName
        );*/

        var promptName = mlParams.LlmSystemPrompt + permissionSuffix;
        string contextFileName;

        string[] splitFileName = mlParams.LlmContextFileName.Split(new string[] { ".gguf" }, StringSplitOptions.None);

        if (splitFileName.Length > 1)
        {
            contextFileName = splitFileName[0] + permissionSuffix + ".gguf";
        }
        else
        {
            contextFileName = mlParams.LlmContextFileName + permissionSuffix;
        }
        startInfo.FileName = $"{mlParams.LlmModelPath}llama.cpp/llama-cli";
        startInfo.Arguments = $" -c {mlParams.LlmCtxSize} -n {mlParams.LlmPromptTokens} -m {mlParams.LlmModelPath + mlParams.LlmModelFileName}  --prompt-cache {mlParams.LlmModelPath + contextFileName} --prompt-cache-ro  -f {mlParams.LlmModelPath + promptName} {mlParams.LlmPromptMode} -r \"{mlParams.LlmReversePrompt}\" {extraReversePrompt}  --keep -1 --temp 0 -t {mlParams.LlmThreads} {promptPrefix}";
        _logger.LogInformation($"Running command : {startInfo.FileName}{startInfo.Arguments}");
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardInput = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.CreateNoWindow = true;
    }
    public async Task StartProcess(LLMServiceObj serviceObj, DateTime currentTime)
    {
        _isStateStarting = true;
        _isStateReady = false;
        if (_mlParams.StartOnlyOneFreeLLM && serviceObj.LlmChainStartName != "monitor") return ;// throw new Exception($"The advanced {serviceObj.LlmChainStartName} assistant is only available with TurboLLM. However the basic monitor assistant is still available");
        await _processRunnerSemaphore.WaitAsync(); // Wait to enter the semaphore
        try
        {

            if (_processes.ContainsKey(serviceObj.SessionId))
                throw new Exception("FreeLLM Assistant already running");
            _logger.LogInformation($" LLM Service : Start Process for sessionsId {serviceObj.SessionId}");
            ProcessWrapper process;
            process = new ProcessWrapper();
            SetStartInfo(process.StartInfo, _mlParams);
            process.Start();
            await WaitForReadySignal(process);
            _processes[serviceObj.SessionId] = process;
        }
        catch
        {
            _isStateStarting = false;
            _isStateReady = true;
            _isStateFailed = true;
            throw;
        }
        finally
        {
            _processRunnerSemaphore.Release(); // Release the semaphore
        }
        string input = "";
        string userInput = "";
        if (_mlParams.LlmVersion == "func_2.4") userInput = $"<|from|> get_login_info\\\n<|recipient|> all\\\n<|content|>User info ";
        else if (_mlParams.LlmVersion == "func_2.5") userInput = $"<|start_header_id|>tool<|end_header_id|>name=get_user_info";
        else if (_mlParams.LlmVersion == "func_3.1") userInput = "<|start_header_id|>ipython<|end_header_id|>";
        else if (_mlParams.LlmVersion == "func_3.2") userInput = $"<|start_header_id|>tool<|end_header_id|>";
        else if (_mlParams.LlmVersion == "llama_3.2") userInput = $"<|start_header_id|>ipython<|end_header_id|>";
        
        else if (_mlParams.LlmVersion == "standard") userInput = "Function Call : ";

        if (serviceObj.IsUserLoggedIn)
        {
            var user = new UserInfo()
            {
                Email = serviceObj.UserInfo.Email,
            };
           
            input += PrintPropertiesAsJson.PrintUserInfoPropertiesWithDate(user, serviceObj.IsUserLoggedIn, currentTime.ToString("yyyy-MM-ddTHH:mm:ss"), false);

        }
        else
        {
            var user = new UserInfo();
            input = PrintPropertiesAsJson.PrintUserInfoPropertiesWithDate(user, serviceObj.IsUserLoggedIn, currentTime.ToString("yyyy-MM-ddTHH:mm:ss"), false);
        }
        serviceObj.UserInput = userInput + input;

        if (_mlParams.LlmVersion == "func_2.5" || _mlParams.LlmVersion == "func_3.2" || _mlParams.LlmVersion == "llama_3.2" )  serviceObj.UserInput ="<|start_header_id|>user<|end_header_id|>whats my user info<|eot_id|>";
      

        serviceObj.IsFunctionCallResponse = false;
        _sendOutput = false;
        await SendInputAndGetResponse(serviceObj);

        _logger.LogInformation($"LLM process started for session {serviceObj.SessionId}");
        _sendOutput = true;
        _isStateStarting = false;
        _isStateReady = true;
        _isStateFailed = false;
    }
    public async Task RemoveProcess(string sessionId)
    {
        _isStateReady = false;

        if (!_processes.TryGetValue(sessionId, out var process))
        {
            _isStateReady = true;
            throw new Exception("Process is not running for this session");
        }
        // Stop broadcaster if running.
        ITokenBroadcaster? tokenBroadcaster;
        if (_tokenBroadcasters.TryGetValue(sessionId, out tokenBroadcaster))
        {
            await tokenBroadcaster.ReInit(sessionId);
            _tokenBroadcasters.TryRemove(sessionId, out _);
        }
        _logger.LogInformation($" LLM Service : Remove Process for sessionsId {sessionId}");
        try
        {
            if (process != null && !process.HasExited)
            {
                process.Kill();
                await Task.Delay(5000);
                // Send second kill as it needs two ctrl-c to exit llama-cli
                if (process != null && !process.HasExited)
                {
                    process.Kill();
                }
            }
        }
        finally
        {
            _isStateFailed = true;
            _isStateReady = true;
            if (process != null)
            {
                process.Dispose();
                _processes.TryRemove(sessionId, out _);
            }
        }

        _logger.LogInformation($"LLM process removed for session {sessionId}");
    }

    public void SendCtrlC(string sessionId)
    {
        _isStateReady = false;

        if (!_processes.TryGetValue(sessionId, out var process))
        {
            _isStateReady = true;
            throw new Exception("Process is not running for this session");
        }

        _logger.LogInformation($" LLM Service : Send CtrlC to sessionsId {sessionId}");
        try
        {
            if (process != null && !process.HasExited)
            {
                process.Kill();
            }
        }
        catch (Exception e)
        {
            _logger.LogInformation($"Failed to send CtrlC to session {sessionId}. Error was : {e.Message}");
        }


    }
    private async Task WaitForReadySignal(ProcessWrapper process)
    {
        bool isReady = false;
        string line;
        //await Task.Delay(10000);
        var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.CancelAfter(TimeSpan.FromSeconds(_mlParams.LlmSystemPromptTimeout)); // Timeout after one minute
        while (!cancellationTokenSource.IsCancellationRequested)
        {
            line = await process.StandardOutput.ReadLineAsync();
            if (line.Contains("LLM_STARTED"))
            {
                isReady = true;
                break;
            }
        }
        if (!isReady)
        {
            throw new Exception("FreeLLM Assistant is currently handling a high volume of requests. Please try again later or consider switching to TurboLLM Assistant for a super fast uninterrupted service.");
        }
        _logger.LogInformation($" LLMService Process Started ");
    }
    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
        _isStateReady = false;
        await _processRunnerSemaphore.WaitAsync();
        CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(_mlParams.LlmUserPromptTimeout)); // Default timeout is 30 seconds, can be adjusted

        try
        {
            _logger.LogInformation($"  LLMService : SendInputAndGetResponse() :");
            if (!_processes.TryGetValue(serviceObj.SessionId, out var process))
            {
                _isStateFailed = true;
                _isStateReady = true;
                throw new Exception($"No Assistant found for sessionId= {serviceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
            }
            if (process == null || process.HasExited)
            {
                _isStateFailed = true;
                _isStateReady = true;
                throw new InvalidOperationException("FreeLLM Assistant is not running.  Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
            }
            if (_isStateFailed)
            {
                _isStateReady = true;
                throw new InvalidOperationException("FreeLLM Assistant is in a failed state.  Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
            }
            process.LastActivity = DateTime.UtcNow;
            ITokenBroadcaster? tokenBroadcaster;
            if (_tokenBroadcasters.TryGetValue(serviceObj.SessionId, out tokenBroadcaster))
            {
                await tokenBroadcaster.ReInit(serviceObj.SessionId);
            }
            else
            {
                if (_mlParams.LlmVersion == "func_2.4") tokenBroadcaster = new TokenBroadcasterFunc_2_4(_responseProcessor, _logger);
                else if (_mlParams.LlmVersion == "func_2.5") tokenBroadcaster = new TokenBroadcasterFunc_2_5(_responseProcessor, _logger);
                else if (_mlParams.LlmVersion == "func_3.1") tokenBroadcaster = new TokenBroadcasterFunc_3_1(_responseProcessor, _logger);
                 else if (_mlParams.LlmVersion == "func_3.2") tokenBroadcaster = new TokenBroadcasterFunc_3_2(_responseProcessor, _logger);
                else if (_mlParams.LlmVersion == "llama_3.2") tokenBroadcaster = new TokenBroadcasterLlama_3_2(_responseProcessor, _logger);
                
                else if (_mlParams.LlmVersion == "standard") tokenBroadcaster = new TokenBroadcasterStandard(_responseProcessor, _logger);

                else throw new InvalidOperationException($" Error there is no Token Broadcaster for LLM Version {_mlParams.LlmVersion}");

            }
            string userInput = serviceObj.UserInput;

            if (_sendOutput)
            {
                userInput = userInput.Replace("\r\n", "\\\n").Replace("\n", "\\\n");
                if (!serviceObj.IsFunctionCallResponse)
                {
                    if (_mlParams.LlmVersion == "func_2.4") userInput = "<|from|> user\\\n<|recipient|> all\\\n<|content|>" + userInput;
                    else if (_mlParams.LlmVersion == "func_2.5") userInput = "<|start_header_id|>user<|end_header_id|>" + userInput+"<|eot_id|>";
                    else if (_mlParams.LlmVersion == "func_3.1") userInput = "<|start_header_id|>user<|end_header_id|>" + userInput+"<|eot_id|>";
                    else if (_mlParams.LlmVersion == "func_3.2") userInput = "<|start_header_id|>user<|end_header_id|>" + userInput+"<|eot_id|>";
                   else if (_mlParams.LlmVersion == "llama_3.2") userInput = "<|start_header_id|>user<|end_header_id|>" + userInput+"<|eot_id|>";
                   
                    else if (_mlParams.LlmVersion=="standard") userInput = userInput;

                }
                else
                {
                    if (_mlParams.LlmVersion == "func_2.4") userInput = "<|from|> " + serviceObj.FunctionName + "\\\n<|recipient|> all\\\n<|content|>" + serviceObj.UserInput;
                    else if (_mlParams.LlmVersion == "func_2.5") userInput = "<|start_header_id|>tool<|end_header_id|>name=" + serviceObj.FunctionName + " " + serviceObj.UserInput+"<|eot_id|>";
                    else if (_mlParams.LlmVersion == "func_3.1") userInput = "<|start_header_id|>ipython<|end_header_id|>" + serviceObj.UserInput+"<|eot_id|>";
                    else if (_mlParams.LlmVersion == "func_3.2") userInput = "<|start_header_id|>tool<|end_header_id|>" + serviceObj.UserInput+"<|eot_id|>";
                    else if (_mlParams.LlmVersion == "llama_3.2") userInput = "<|start_header_id|>ipython<|end_header_id|>" + serviceObj.UserInput+"<|eot_id|>";
                    else if (_mlParams.LlmVersion=="standard") userInput = "Funtion Call: "+serviceObj.UserInput;
                }
            }

            await process.StandardInput.WriteLineAsync(userInput);
            await process.StandardInput.FlushAsync();
            _logger.LogInformation($" ProcessLLMOutput(user input) -> {userInput}");
            // Wait for a response or a timeout
            Task broadcastTask = tokenBroadcaster.BroadcastAsync(process, serviceObj, userInput, _sendOutput);
            if (await Task.WhenAny(broadcastTask, Task.Delay(Timeout.Infinite, cts.Token)) == broadcastTask)
            {
                // Task completed within timeout
                await broadcastTask;
            }
            else
            {

                _logger.LogWarning($"Session  {serviceObj.SessionId} timed out. Terminating process.");
                await RemoveProcess(serviceObj.SessionId);
                _isStateFailed = true;
                _isStateReady = true;
                throw new Exception("FreeLLM Assistant is currently handling a high volume of requests. Please try again later or consider switching to TurboLLM Assistant for a super fast uninterrupted service.");

            }
        }
        catch
        {
            throw;
        }
        finally
        {
            _processRunnerSemaphore.Release(); // Release the semaphore
            _isStateReady = true;
        }
    }
}

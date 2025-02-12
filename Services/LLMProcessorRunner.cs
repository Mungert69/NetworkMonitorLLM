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
    private readonly ConcurrentDictionary<string, List<LLMServiceObj>> _pendingResponses = new();
    private bool _sendOutput = false;
    private ILogger _logger;
    private ILLMResponseProcessor _responseProcessor;
    private MLParams _mlParams;
    private Timer _idleCheckTimer;
    private int _llmLoad;
    private SemaphoreSlim _processRunnerSemaphore;

    public string Type { get => "FreeLLM"; }
    private bool _isStateReady = false;
    private bool _isStateStarting = false;
    private bool _isStateFailed = false;
    private bool _isEnabled = false;
    private string _serviceID;
    private LLMConfig _config;
    private LLMServiceObj _startServiceoObj;

    public bool IsStateReady { get => _isStateReady; }
    public bool IsStateStarting { get => _isStateStarting; }
    public bool IsStateFailed { get => _isStateFailed; }
    public bool IsEnabled { get => _isEnabled; }
    public int LlmLoad { get => _llmLoad; set => _llmLoad = value; }

    public event Action<int, string> LoadChanged;
     public event Func<string, LLMServiceObj, Task> OnUserMessage;
     public event Func<LLMServiceObj, Task> SendHistory;
    public event Func<string, LLMServiceObj, Task> RemoveSavedSession;
    private IAudioGenerator _audioGenerator;

    private ConcurrentDictionary<string, StringBuilder?> _assistantMessages = new ConcurrentDictionary<string, StringBuilder?>();

    public LLMProcessRunner(ILogger<LLMProcessRunner> logger, ILLMResponseProcessor responseProcessor, ISystemParamsHelper systemParamsHelper, LLMServiceObj startServiceObj, SemaphoreSlim processRunnerSemaphore, IAudioGenerator audioGenerator)
    {
        _logger = logger;
        _responseProcessor = responseProcessor;
        _startServiceoObj = startServiceObj;
        _mlParams = systemParamsHelper.GetMLParams();
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _processRunnerSemaphore = processRunnerSemaphore;
        _audioGenerator= audioGenerator;
        _idleCheckTimer = new Timer(async _ => await CheckAndTerminateIdleProcesses(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        _isEnabled = _mlParams.StartThisFreeLLM;
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
        string promptSuffix=$" --in-suffix \"{_config.EOTToken}{_config.AssistantHeader}\" ";

        if (_startServiceoObj.UserInfo.AccountType == null)
        {
            _startServiceoObj.UserInfo.AccountType = "Free";
            _logger.LogError($" Error : User {_startServiceoObj.UserInfo.UserID} account type is null setting to Free as default");
        }

        string permissionSuffix = "";
        // Old way of doing permission is to load different context. new way is to let the api deal with it
        /*string permissionSuffix = "_free";
        if (!_mlParams.StartThisFreeLLM) permissionSuffix = AccountTypeFactory.GetPermissionSuffix(
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
        string reversePrompt=$"-r \"{_config.EOTToken}\" ";
        if (!string.IsNullOrEmpty(_config.EOMToken)) reversePrompt+=$"-r \"{_config.EOMToken}\" ";
        startInfo.FileName = $"{mlParams.LlmModelPath}llama.cpp/llama-cli";
        startInfo.Arguments = $" -c {mlParams.LlmCtxSize} -n {mlParams.LlmPromptTokens} -m {mlParams.LlmModelPath + mlParams.LlmModelFileName}  --prompt-cache {mlParams.LlmModelPath + contextFileName} --prompt-cache-ro  -f {mlParams.LlmModelPath + promptName} {mlParams.LlmPromptMode} {reversePrompt} {promptSuffix} --keep -1 --temp {mlParams.LlmTemp} -t {mlParams.LlmThreads} {promptPrefix}";
        _logger.LogInformation($"Running command : {startInfo.FileName}{startInfo.Arguments}");
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardInput = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.CreateNoWindow = true;
    }
    public async Task StartProcess(LLMServiceObj serviceObj)
    {
         _config = LLMConfigFactory.GetConfig(_mlParams.LlmVersion);

        if (!_mlParams.StartThisFreeLLM || _isStateStarting) return;
        _isStateStarting = true;
        _isStateReady = false;
        _isStateFailed = false;
        if (_llmLoad > 0)
        {
            var chunkServiceObj = new LLMServiceObj(serviceObj)
            {
                LlmMessage = $"<load-count>{_llmLoad}</load-count>"
            };
            if (serviceObj.IsPrimaryLlm)
                await _responseProcessor.ProcessLLMOutput(chunkServiceObj);
        }

        LoadChanged?.Invoke(1, Type);
        await _processRunnerSemaphore.WaitAsync();
        try
        {
            _responseProcessor.IsManagedMultiFunc = false;
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
            _isStateFailed = true;
            throw;
        }
        finally
        {
            _isStateStarting = false;
            _isStateReady = true;
            _processRunnerSemaphore.Release();
            LoadChanged?.Invoke(-1, Type); // Increment load for this type

        }


       
        var userInfo = serviceObj.IsUserLoggedIn
            ? new UserInfo { Email = serviceObj.UserInfo.Email }
            : new UserInfo();

        string functionResponse = string.Format(
            _config.FunctionResponseTemplate,
            "get_user_info",
            PrintPropertiesAsJson.PrintUserInfoPropertiesWithDate(
                userInfo,
                serviceObj.IsUserLoggedIn,
                serviceObj.GetClientStartTime().ToString("yyyy-MM-ddTHH:mm:ss"),
                false
            )
        );

        serviceObj.UserInput = functionResponse;
        // We have to set it as a not call as the function call is already in the history or context. so this is just user input as a function response 
        serviceObj.SetAsNotCall();
        _sendOutput = false;
        if (!_mlParams.LlmNoInitMessage) await SendInputAndGetResponse(serviceObj);

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

        if (_tokenBroadcasters.TryRemove(sessionId, out var tokenBroadcaster))
        {
            try
            {
                // Call ReInit to gracefully cancel any ongoing operations
                await tokenBroadcaster.ReInit(sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to reinitialize token broadcaster for sessionId {sessionId}: {ex.Message}");
            }
            finally
            {
                // Dispose of the token broadcaster if it implements IDisposable
                if (tokenBroadcaster is IDisposable disposableBroadcaster)
                {
                    disposableBroadcaster.Dispose();
                }

                // Nullify the reference to ensure cleanup
                tokenBroadcaster = null;
            }
        }


        _logger.LogInformation($"LLM Service: Attempting to remove process for sessionId {sessionId}");
        try
        {
            if (process != null && !process.HasExited)
            {
                // Send kill signal
                process.Kill();

                // Wait for process to exit
                if (!process.WaitForExit(5000)) // Wait 5 seconds
                {
                    _logger.LogWarning($"Process for sessionId {sessionId} did not exit after first Kill attempt. Retrying...");
                    process.Kill(); // Retry kill
                    if (!process.WaitForExit(3000)) // Wait additional 3 seconds
                    {
                        _logger.LogWarning($"Process did not exit gracefully for sessionId {sessionId}. Attempting forceful termination.");
                        ProcessKiller.ForceKillProcess(process);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error occurred while removing process for sessionId {sessionId}: {ex.Message}");
            _logger.LogError($"Error while shutting down process for sessionId {sessionId}: {ex.Message}");
            ProcessKiller.ForceKillProcess(process);
        }
        finally
        {
            try
            {
                if (process != null)
                {
                    process.Dispose();
                    process = null;

                }

            }
            catch { }
            finally
            {
                _processes.TryRemove(sessionId, out _);
            }

            _isStateFailed = true;
            _isStateReady = true;
        }

        _logger.LogInformation($"LLM process successfully removed for sessionId {sessionId}");
    }


    public async Task StopRequest(string sessionId)
    {
        _isStateReady = false;

        if (!_processes.TryGetValue(sessionId, out var process))
        {
            _isStateReady = true;
            throw new Exception("Process is not running for this session");
        }
        if (_tokenBroadcasters.TryGetValue(sessionId, out var tokenBroadcaster))
        {
            try
            {
                await tokenBroadcaster.ReInit(sessionId);
                _logger.LogInformation($" Success : Stop tokenBroadCaster for sessionId {sessionId}");

            }
            catch (Exception ex)
            {
                _logger.LogError($" Error : failed to reinitialize token broadcaster for sessionId {sessionId}: {ex.Message}");
            }
        }
        else
        {
            _logger.LogWarning($" Warning : No tokenBroadCasters found for sessionId {sessionId}");

        }



        try
        {
            if (process != null && !process.HasExited)
            {
                ProcessSignalHelper.SendCtrlCSignal(process.UnderlyingProcess);
                _logger.LogInformation($" Success : sent Ctrl-C for sessionId {sessionId}");

            }
        }
        catch (Exception e)
        {
            _logger.LogError($" Error : Failed to send Ctrl+C to session {sessionId}. Error: {e.Message}");
        }

        _isStateReady = true;

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

            if (line != null && (line.Trim() == "<|eot_id|>" || line.Trim() == "<|im_end|>" || line.Trim() == "<|LLM_STARTED|>"))
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
    private string EOTToken()
    {
        return _config.EOTToken ?? string.Empty;
    }

    private string FunctionResponseBuilder(LLMServiceObj pendingServiceObj)
    {
        // Replace line breaks with spaces
        string userInput = pendingServiceObj.UserInput.Replace("\r\n", " ").Replace("\n", " ");

        /*if (pendingServiceObj.FunctionName != "are_functions_running")
        {
            int firstBraceIndex = userInput.IndexOf('{');
            if (firstBraceIndex != -1)
            {
                // Insert the new field after the first '{'
                string messageIdField = $"\"message_id\" : \"{pendingServiceObj.MessageID}\", ";
                userInput = userInput.Insert(firstBraceIndex + 1, messageIdField);
            }
        }*/

        // Return the formatted response
        return string.Format(_config.FunctionResponseTemplate, pendingServiceObj.FunctionName, userInput);
    }


    public async Task SendInputAndGetResponse(LLMServiceObj serviceObj)
    {
          if (serviceObj.UserInput.StartsWith("<|REMOVE_SAVED_SESSION|>"))
        {
            string fullSessionId = serviceObj.UserInput.Replace("<|REMOVE_SAVED_SESSION|>", string.Empty).Trim();
             if (!string.IsNullOrEmpty(fullSessionId) && RemoveSavedSession != null)
            {

                 await RemoveSavedSession.Invoke(fullSessionId, serviceObj);

                _logger.LogInformation($"Success: Removed saved sessionId {fullSessionId}");
            }
            else
            {
                _logger.LogWarning("Warning: Empty or invalid session ID after removing prefix.");
            }
            return;
        }
         if (serviceObj.UserInput == "<|REPLAY_HISTORY|>")
        {
            // TODO implement a caching mech for getting previoud contexts
            //await ReplayHistory(serviceObj.SessionId);
            _logger.LogInformation($" Replay history  not yet implemented for sessionId {serviceObj.SessionId}");
            return;
        }
         if (serviceObj.UserInput == "<|REPLAY_HISTORY|>")
        {
            // TODO implement a caching mech for getting previoud contexts
            //await ReplayHistory(serviceObj.SessionId);
            _logger.LogInformation($" Replayed history for sessionId {serviceObj.SessionId}");
            return;
        }
        if (serviceObj.UserInput.Contains("<|START_AUDIO|>") || serviceObj.UserInput.Contains("<|STOP_AUDIO|>")) {
               throw new Exception($"Audio is not available for the FreeLLM. Switch to another LLM if you need audio output.");
         
        }
        _isStateReady = false;
        string tokenBroadcasterMessage = "";
        int sendLlmLoad = 0;
        if (_llmLoad > 0)
        {
            sendLlmLoad = _llmLoad;
        }
        LoadChanged?.Invoke(1, Type);
        CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(_mlParams.LlmUserPromptTimeout)); // Default timeout is 30 seconds, can be adjusted
        await _processRunnerSemaphore.WaitAsync();
        try
        {
            _logger.LogInformation($"  LLMService : SendInputAndGetResponse() :");
            if (!_processes.TryGetValue(serviceObj.SessionId, out var process))
            {
                _isStateFailed = true;
                throw new Exception($"No Assistant found for sessionId= {serviceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
            }
            if (process == null || process.HasExited)
            {
                _isStateFailed = true;
                throw new InvalidOperationException("FreeLLM Assistant is not running.  Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
            }
            if (_isStateFailed)
            {
                throw new InvalidOperationException("FreeLLM Assistant is in a failed state.  Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click");
            }
            process.LastActivity = DateTime.UtcNow;
            ITokenBroadcaster? tokenBroadcaster;
            // Check if all function calls for this MessageID have been processed
            if (serviceObj.IsFunctionCallResponse && !serviceObj.IsFunctionCallStatus)
            {
                if (!serviceObj.IsFunctionStillRunning)
                {
                    _responseProcessor.MarkFunctionAsProcessed(serviceObj);
                    bool allResponsesReady = _responseProcessor.AreAllFunctionsProcessed(serviceObj.MessageID);
                    if (!allResponsesReady)
                    {
                        _logger.LogInformation("Waiting for additional function calls to complete.");
                        return;
                    }
                    else
                    {
                        _assistantMessages.TryRemove(serviceObj.MessageID, out _);
                    }

                }
                else
                {
                    //TODO work out how to use function still running messages
                    _logger.LogInformation("Ignoring FunctionStillRunning message.");
                    return;
                }


            }

            if (_tokenBroadcasters.TryGetValue(serviceObj.SessionId, out tokenBroadcaster))
            {
                await tokenBroadcaster.ReInit(serviceObj.SessionId);
            }
            else
            {
                tokenBroadcaster = _config.CreateBroadcaster(_responseProcessor, _logger, _mlParams.XmlFunctionParsing);

                if (!_tokenBroadcasters.TryAdd(serviceObj.SessionId, tokenBroadcaster))
                {
                    _logger.LogError($"Failed to add TokenBroadcaster for sessionId {serviceObj.SessionId}");
                    throw new InvalidOperationException($"Failed to add TokenBroadcaster for sessionId {serviceObj.SessionId}");
                }
                tokenBroadcaster.Init(_config);

            }
            string userInput = serviceObj.UserInput;
            var preAssistantMessage = "";
            var functionStatusMessage = "";
            if (_sendOutput)
            {
                preAssistantMessage = string.Join("", _assistantMessages.Select(entry =>
              {
                  var assistantMessage = entry.Value?.ToString() ?? string.Empty;
                  return string.Format(_config.AssistantMessageTemplate, assistantMessage);
              }));


                _assistantMessages.Clear();
                userInput = userInput.Replace("\r\n", " ").Replace("\n", " ");

                //userInput = userInput.Replace("\r\n", "\\\n").Replace("\n", "\\\n");
                if (!serviceObj.IsFunctionCallResponse)
                {

                    userInput = string.Format(_config.UserInputTemplate, userInput);

                }
                else if (!serviceObj.IsFunctionCallStatus)
                {
                    var processedFunctionCalls = _responseProcessor.GetProcessedFunctionCalls(serviceObj.MessageID);
                    var constructedInputs = processedFunctionCalls.Select((pendingServiceObj, index) =>
                        {
                            userInput = FunctionResponseBuilder(pendingServiceObj);
                            // Add "<|eot_id|>" etc. if it's not the last item
                            if (index < processedFunctionCalls.Count - 1)
                            {
                                userInput = userInput + EOTToken();
                            }

                            return userInput;
                        });

                    // Combine the constructed inputs for all responses
                    userInput = string.Join("", constructedInputs);
                    _responseProcessor.ClearFunctionCallTracker(serviceObj.MessageID);
                }
                else
                {
                    functionStatusMessage = FunctionResponseBuilder(serviceObj) + EOTToken();
                }
            }


            string llmInput = preAssistantMessage + functionStatusMessage + userInput;
            if (string.IsNullOrEmpty(llmInput))
            {
                _logger.LogWarning(" Warning : LLM Input is empty");
                return;
            }
            await tokenBroadcaster.SetUp( serviceObj, _sendOutput, sendLlmLoad);
            await process.StandardInput.WriteLineAsync(llmInput);
            await process.StandardInput.FlushAsync();
            _logger.LogInformation($" LLM INPUT -> {llmInput}");
            // Wait for a response or a timeout
            Task broadcastTask = tokenBroadcaster.BroadcastAsync(process, serviceObj, userInput);
            if (await Task.WhenAny(broadcastTask, Task.Delay(Timeout.Infinite, cts.Token)) == broadcastTask)
            {
                // Task completed within timeout
                await broadcastTask;
                if (tokenBroadcaster.AssistantMessage != null)
                {
                    if (tokenBroadcaster.AssistantMessage != null) _assistantMessages.TryAdd(serviceObj.MessageID, tokenBroadcaster.AssistantMessage);
                    tokenBroadcaster.AssistantMessage = null;
                }
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
        finally
        {

            _processRunnerSemaphore.Release();
            _isStateReady = true;
            LoadChanged?.Invoke(-1, Type);

        }
    }
}

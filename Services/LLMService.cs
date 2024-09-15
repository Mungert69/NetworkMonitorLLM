using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.LLM.Services.Objects;
using NetworkMonitor.Utils;
using NetworkMonitor.Utils.Helpers;

namespace NetworkMonitor.LLM.Services;
// LLMService.cs
public interface ILLMService
{
    Task<LLMServiceObj> StartProcess(LLMServiceObj llmServiceObj);
    Task<LLMServiceObj> RemoveProcess(LLMServiceObj llmServiceObj);
    Task<ResultObj> SendInputAndGetResponse(LLMServiceObj serviceObj);
}

public class LLMService : ILLMService
{
    private ILogger _logger;

    private readonly ILLMProcessRunnerFactory _processRunnerFactory;
    private readonly IOpenAIRunnerFactory _openAIRunnerFactory;
    private IServiceProvider _serviceProvider;
    private IRabbitRepo _rabbitRepo;
    private SemaphoreSlim _processRunnerSemaphore = new SemaphoreSlim(1);
    private SemaphoreSlim _openAIRunnerSemaphore = new SemaphoreSlim(10);
    private MLParams _mlParams;
    private string _serviceID;
    private readonly ConcurrentDictionary<string, Session> _sessions = new ConcurrentDictionary<string, Session>();
    // private readonly ILLMResponseProcessor _responseProcessor;

    public LLMService(ILogger<LLMService> logger, IRabbitRepo rabbitRepo, ISystemParamsHelper systemParamsHelper, IServiceProvider serviceProvider)
    {
        _processRunnerFactory = new LLMProcessRunnerFactory();
        _openAIRunnerFactory = new OpenAIRunnerFactory();
        _serviceProvider = serviceProvider;
        _rabbitRepo = rabbitRepo;
        _mlParams = systemParamsHelper.GetMLParams();
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _logger = logger;
    }
    public async Task<LLMServiceObj> StartProcess(LLMServiceObj llmServiceObj)
    {
        llmServiceObj.SessionId = llmServiceObj.RequestSessionId;
        try
        {
            DateTime usersCurrentTime = DateTime.UtcNow;
            try
            {
                var clientTimeZone = llmServiceObj.TimeZone != null
                                            ? TimeZoneInfo.FindSystemTimeZoneById(llmServiceObj.TimeZone)
                                            : TimeZoneInfo.Utc;
                usersCurrentTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, clientTimeZone);
            }
            catch
            { // Just continue and use Utc time zone
            }

            bool exists = _sessions.TryGetValue(llmServiceObj.SessionId, out var checkSession);
            bool isSessionRemoved = false;
            if (checkSession != null && checkSession.Runner != null && checkSession.Runner.Type! == llmServiceObj.LLMRunnerType && checkSession.Runner.IsStateFailed)
            {
                try
                {
                    await checkSession.Runner.RemoveProcess(llmServiceObj.SessionId);
                    isSessionRemoved = true;
                }
                catch
                {// just try to remove don't catch  }

                }
            }
            if (isSessionRemoved || checkSession == null || (checkSession != null && checkSession.Runner != null && checkSession.Runner.Type! != llmServiceObj.LLMRunnerType))
            {
                ILLMRunner runner;
                switch (llmServiceObj.LLMRunnerType)
                {
                    case "TurboLLM":
                        runner = _openAIRunnerFactory.CreateRunner(_serviceProvider, llmServiceObj, _openAIRunnerSemaphore);
                        break;
                    case "FreeLLM":
                        runner = _processRunnerFactory.CreateRunner(_serviceProvider, llmServiceObj, _processRunnerSemaphore);
                        break;
                    // Add more cases for other runner types if needed
                    default:
                        throw new ArgumentException($"Invalid runner type: {llmServiceObj.LLMRunnerType}");
                }
                string extraMesage = "";
                if (llmServiceObj.LLMRunnerType == "FreeLLM") extraMesage = $" , this can take up to {_mlParams.LlmSystemPromptTimeout} seconds. If the session is not used for {_mlParams.LlmSessionIdleTimeout} minutes it will be closed";
                llmServiceObj.LlmMessage = MessageHelper.InfoMessage($" Starting {llmServiceObj.LLMRunnerType} {_serviceID} Assistant {extraMesage}");
                await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);


                await runner.StartProcess(llmServiceObj, usersCurrentTime);
                _sessions[llmServiceObj.SessionId] = new Session { Runner = runner };
                llmServiceObj.ResultMessage = $" Success {runner.Type} {_serviceID} Assistant Started";
                llmServiceObj.ResultSuccess = true;
                llmServiceObj.LlmMessage = MessageHelper.SuccessMessage(llmServiceObj.ResultMessage);
                await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
            }
            else
            {
                llmServiceObj.ResultMessage = $"{llmServiceObj.LlmChainStartName} Info Assistant already running so it was not reloaded";
                llmServiceObj.ResultSuccess = true;
                llmServiceObj.LlmMessage = MessageHelper.InfoMessage(llmServiceObj.ResultMessage);
                await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
            }
            await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceStarted", llmServiceObj);
        }
        catch (Exception e)
        {
            llmServiceObj.ResultMessage = $" Error : Could not start {llmServiceObj.LlmChainStartName} Info Assistant. Error was : {e.Message}";
            llmServiceObj.ResultSuccess = false;
            llmServiceObj.LlmMessage = MessageHelper.ErrorMessage(llmServiceObj.ResultMessage);
            await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
            _logger.LogError(llmServiceObj.ResultMessage);
        }


        return llmServiceObj;
    }

    public async Task<LLMServiceObj> RemoveProcess(LLMServiceObj llmServiceObj)
    {
        try
        {
            if (_sessions.TryGetValue(llmServiceObj.SessionId, out var session))
            {
                if (session.Runner != null)
                {
                    await session.Runner.RemoveProcess(llmServiceObj.SessionId);
                    _sessions.TryRemove(llmServiceObj.SessionId, out _);
                    await _rabbitRepo.PublishAsync<LLMServiceObj>("llmSessionEnded", llmServiceObj);

                    llmServiceObj.ResultMessage = $" Success : LLMService Removed Session and sent LLM Session Ended message for sessionId {llmServiceObj.SessionId}.";
                    llmServiceObj.ResultSuccess = true;
                }
                else
                {
                    llmServiceObj.ResultMessage = $" Error : LLMService trying to remove process the runner is already null for sessionId {llmServiceObj.SessionId}.";
                    llmServiceObj.ResultSuccess = false;
                }
            }
            else
            {
                llmServiceObj.ResultMessage = $" Error : Could not find session {llmServiceObj.SessionId} to remove the process .";
                llmServiceObj.ResultSuccess = false;
            }


        }
        catch (Exception e)
        {
            llmServiceObj.ResultMessage = e.Message;
            llmServiceObj.ResultSuccess = false;
        }


        return llmServiceObj;
    }


    public async Task<ResultObj> SendInputAndGetResponse(LLMServiceObj llmServiceObj)
    {
        var result = new ResultObj();
        Session? session = null;
        //bool isWarning = false;

        if (llmServiceObj.SessionId == null || !_sessions.TryGetValue(llmServiceObj.SessionId, out session))
        {
            result.Message = $" No Assistant found for sessionId={llmServiceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problems persists contact support@freenetworkmontior.click";
            result.Success = false;

        }
        else
        {
            try
            {
                result.Success = true;
                 if (session.Runner == null)
                {
                     result.Message = " Error : the assistant has no running process";
                    result.Success = false;
                    llmServiceObj.LlmMessage = MessageHelper.ErrorMessage(result.Message);
                    await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
                    return result;
              
                }
                
                if (session.Runner.IsStateStarting)
                {
                    result.Message = " Please wait the assistant is starting...";
                    result.Success = false;
                    llmServiceObj.LlmMessage = MessageHelper.WarningMessage(result.Message);
                    await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
                }

                if (!session.Runner.IsStateReady)
                {
                    result.Message = " Please wait the assistant is processing the last message..." + llmServiceObj.UserInput;
                    result.Success = false;
                    llmServiceObj.LlmMessage = MessageHelper.WarningMessage(result.Message);
                    await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
                }
                if (session.Runner.IsStateFailed)
                {
                    result.Message = " The Assistant is stopped try reloading or refresh the page";
                    result.Success = false;
                    llmServiceObj.LlmMessage = MessageHelper.ErrorMessage(result.Message);
                    await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
                }

                if (result.Success)
                {
                    await session.Runner.SendInputAndGetResponse(llmServiceObj);
                    result.Message = " Processed UserInput :" + llmServiceObj.UserInput;
                }
            }
            catch (Exception e)
            {
                result.Message += $" Error : {e.Message}";
                result.Success = false;
                llmServiceObj.LlmMessage = MessageHelper.ErrorMessage(result.Message);
                await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", llmServiceObj);
            }
        }

        return result;
    }

    public void EndSession(string sessionId)
    {
        _sessions.TryRemove(sessionId, out _);
    }
}




// LLMResponseProcessor.cs
public interface ILLMResponseProcessor
{
    Task ProcessLLMOutput(LLMServiceObj serviceObj);
    Task ProcessLLMOuputInChunks(LLMServiceObj serviceObj);
    Task ProcessFunctionCall(LLMServiceObj serviceObj);
    Task ProcessEnd(LLMServiceObj serviceObj);
    Task UpdateTokensUsed(LLMServiceObj serviceObj);
    bool IsFunctionCallResponse(string input);
    bool SendOutput { get; set; }
}

public class LLMResponseProcessor : ILLMResponseProcessor
{

    private IRabbitRepo _rabbitRepo;
    private bool _sendOutput = true;

    public bool SendOutput { get => _sendOutput; set => _sendOutput = value; }

    public LLMResponseProcessor(IRabbitRepo rabbitRepo)
    {

        _rabbitRepo = rabbitRepo;
    }

    public async Task ProcessLLMOutput(LLMServiceObj serviceObj)
    {
        //Console.WriteLine(serviceObj.LlmMessage);
        if (_sendOutput && !string.IsNullOrEmpty(serviceObj.LlmMessage)) await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", serviceObj);
        //return Task.CompletedTask;
    }

    public async Task ProcessLLMOuputInChunks(LLMServiceObj serviceObj)
    {

        char[] delimiters = { ' ', ',', '!', '?', '{', '}', '.', ':' };
        List<string> splitResult = StringUtils.SplitAndPreserveDelimiters(serviceObj.LlmMessage, delimiters);

        foreach (string chunk in splitResult)
        {
            serviceObj.LlmMessage = chunk;
            await ProcessLLMOutput(serviceObj);
            await Task.Delay(50); // Pause between sentences 
        }

    }



    public async Task ProcessEnd(LLMServiceObj serviceObj)
    {
        //Console.WriteLine(serviceObj.LlmMessage);
        serviceObj.LlmMessage = MessageHelper.ErrorMessage(serviceObj.LlmMessage);
        await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceTimeout", serviceObj);
        //return Task.CompletedTask;
    }

    public async Task UpdateTokensUsed(LLMServiceObj serviceObj)
    {
        await _rabbitRepo.PublishAsync<LLMServiceObj>("llmUpdateTokensUsed", serviceObj);
        //return Task.CompletedTask;
    }

    public async Task ProcessFunctionCall(LLMServiceObj serviceObj)
    {
        if (_sendOutput) await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceFunction", serviceObj);

    }

    public bool IsFunctionCallResponse(string input)
    {
        try
        {
            if (string.IsNullOrEmpty(input)) return false;
            FunctionCallData functionCallData = JsonSerializer.Deserialize<FunctionCallData>(input) ?? new FunctionCallData();
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in IsFunctionCallResponse parsing JSON {input}: {ex.Message}");
            return false;
        }
    }

    public bool IsFunctionCallResponseCL(string input)
    {
        try
        {
            if (input == "") return false;
            if (!input.StartsWith("<function>")) return false;

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in IsFunctionCallResponseCL parsing JSON {input}: {ex.Message}");
            return false;
        }
    }
}


public enum ResponseState { Initial, AwaitingInput, FunctionCallProcessed, Completed }



public class Session
{
    public List<string> Responses { get; } = new List<string>();
    public ILLMRunner? Runner { get; set; }
}
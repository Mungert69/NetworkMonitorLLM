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
    Task<ResultObj> RemoveProcess(LLMServiceObj llmServiceObj);
    Task<ResultObj> StopRequest(LLMServiceObj llmServiceObj);
    Task<ResultObj> SendInputAndGetResponse(LLMServiceObj serviceObj);
    Task Init();
}

public class LLMService : ILLMService
{
    private readonly ILogger _logger;

    private readonly IServiceProvider _serviceProvider;
    private readonly IRabbitRepo _rabbitRepo;
    private ILLMFactory _llmFactory;

    private MLParams _mlParams;
    private string _serviceID;
    private  ConcurrentDictionary<string, Session> _sessions = new ConcurrentDictionary<string, Session>();

    public LLMService(ILogger<LLMService> logger, IRabbitRepo rabbitRepo, ISystemParamsHelper systemParamsHelper, IServiceProvider serviceProvider, ILLMFactory llmFactory)
    {

        _serviceProvider = serviceProvider;
        _rabbitRepo = rabbitRepo;
        _mlParams = systemParamsHelper.GetMLParams();
        _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
        _logger = logger;
        _llmFactory = llmFactory;

    }

    public async Task Init()
    {
        _sessions= await  _llmFactory.LoadAllSessionsAsync();
        _llmFactory.Sessions = _sessions;
    }
    public async Task<LLMServiceObj> StartProcess(LLMServiceObj llmServiceObj)
    {
        llmServiceObj.SessionId = llmServiceObj.RequestSessionId + "_" + llmServiceObj.LLMRunnerType;
        try
        {

            bool exists = _sessions.TryGetValue(llmServiceObj.SessionId, out var checkSession);
            //bool isSwapLLMType = false;
            bool isRunnerNull = checkSession == null || checkSession.Runner == null || string.IsNullOrEmpty(checkSession?.Runner?.Type);

            //if (!isRunnerNull && checkSession.Runner.Type != llmServiceObj.LLMRunnerType) isSwapLLMType = true;

            // Create a new runner if there is not one . Or the RunnerType needs to be swapped. Or is the type is the same but its is a failed State
            bool isCreateNewRunner = isRunnerNull || checkSession?.Runner?.IsStateFailed == true;

            if (isCreateNewRunner)
            {
                if (!isRunnerNull)
                    await SafeRemoveRunnerProcess(checkSession, llmServiceObj.SessionId);

                ILLMRunner runner = await _llmFactory.CreateRunner(llmServiceObj.LLMRunnerType, llmServiceObj);
                if (!runner.IsEnabled)
                {
                    //await SetResultMessageAsync(llmServiceObj, $"{llmServiceObj.LLMRunnerType} {_serviceID} not started as it is disabled.", true, "llmServiceMessage");
                    return llmServiceObj;
                }

                string extraMessage = llmServiceObj.LLMRunnerType == "FreeLLM"
                    ? $" , this can take up to {_mlParams.LlmSystemPromptTimeout} seconds..."
                    : "";
                await SetResultMessageAsync(llmServiceObj, $"Starting {llmServiceObj.LLMRunnerType} {_serviceID} Assistant{extraMessage}", true, "llmServiceMessage", true);

                await runner.StartProcess(llmServiceObj);
                _sessions[llmServiceObj.SessionId] = new Session
                {
                    Runner = runner,
                    HistoryDisplayName = new HistoryDisplayName
                    {
                        StartUnixTime = llmServiceObj.GetClientStartUnixTime(),
                        SessionId=llmServiceObj.SessionId,
                        Name="",
                        LlmType=llmServiceObj.LLMRunnerType,
                        UserId=llmServiceObj.UserInfo?.UserID
                    }
                };

                await SetResultMessageAsync(llmServiceObj, $"Success {runner.Type} {_serviceID} Assistant Started", true, "llmServiceMessage", true);
            }
            else
            {
                await _llmFactory.SendHistoryDisplayNames(llmServiceObj);
                await SetResultMessageAsync(llmServiceObj, $"Info: {llmServiceObj.LLMRunnerType} {_serviceID} Assistant already running so it was not reloaded", true, "llmServiceMessage", true);
            }
            await PublishToRabbitMQAsync("llmServiceStarted", llmServiceObj, false);
        }
        catch (Exception e)
        {
            string message = $"Error: Could not start {llmServiceObj.LlmChainStartName} Assistant. Exception: {e.Message}";
            _logger.LogError(e, message);
            await SetResultMessageAsync(
                llmServiceObj,
                message,
                false,
                "llmServiceMessage"
            );
        }

        return llmServiceObj;

    }


    public async Task<ResultObj> RemoveProcess(LLMServiceObj llmServiceObj)
    {
        if (!_sessions.TryGetValue(llmServiceObj.SessionId, out var session))
        {
            return await SetResultMessageAsync(
                llmServiceObj,
                $"Error: Could not find session {llmServiceObj.SessionId} to remove the process.",
                false,
                "llmServiceMessage"
            );
        }

        if (session.Runner == null)
        {
            return await SetResultMessageAsync(
                llmServiceObj,
                $"Error: Runner is already null for session {llmServiceObj.SessionId}.",
                false,
                "llmServiceMessage"
            );
        }

        try
        {
            // Save the conversation history before removing the session
            await _llmFactory.SaveHistoryForSessionAsync(llmServiceObj);

            session.Runner.LoadChanged -= _llmFactory.OnRunnerLoadChanged;
            await session.Runner.RemoveProcess(llmServiceObj.SessionId);
            _sessions.TryRemove(llmServiceObj.SessionId, out _);

            return await SetResultMessageAsync(
                llmServiceObj,
                $"Success {session.Runner.Type} {_serviceID} Assistant stopped",
                true,
                "llmSessionMessage",
                true
            );
        }
        catch (Exception e)
        {
            string message = $"Error removing process for session {llmServiceObj.SessionId}";
            _logger.LogError(e, message);
            return await SetResultMessageAsync(
                llmServiceObj,
                message,
                false,
                "llmServiceMessage"
            );
        }
    }

    public async Task<ResultObj> StopRequest(LLMServiceObj llmServiceObj)
    {
        try
        {
            // Check if the session exists
            if (!_sessions.TryGetValue(llmServiceObj.SessionId, out var session))
            {
                return await SetResultMessageAsync(
                    llmServiceObj,
                    $"Error: Could not find session {llmServiceObj.SessionId} to send stop request.",
                    false,
                    "llmServiceMessage"
                );
            }

            // Check if the Runner is null
            if (session.Runner == null)
            {
                return await SetResultMessageAsync(
                    llmServiceObj,
                    $"Error: Runner is null for session {llmServiceObj.SessionId}.",
                    false,
                    "llmServiceMessage"
                );
            }

            // Stop the Runner
            session.Runner.StopRequest(llmServiceObj.SessionId);

            // Publish success message
            return await SetResultMessageAsync(
                llmServiceObj,
                 $"Success {session.Runner.Type} {_serviceID} Assistant output has been halted",
               true,
                "llmServiceMessage",
                true
            );
        }
        catch (Exception e)
        {
            string errorMessage = $"Error: Unable to stop request for sessionId {llmServiceObj.SessionId}. Exception: {e.Message}";
            _logger.LogError(e, errorMessage);

            // Publish failure message
            return await SetResultMessageAsync(
                llmServiceObj,
                errorMessage,
                false,
                "llmServiceMessage"
            );
        }
    }




    public async Task<ResultObj> SendInputAndGetResponse(LLMServiceObj llmServiceObj)
    {
        try
        {
            // Check if session is valid
            if (string.IsNullOrEmpty(llmServiceObj.SessionId) || !_sessions.TryGetValue(llmServiceObj.SessionId, out var session))
            {
                return await SetResultMessageAsync(
                    llmServiceObj,
                    $"No Assistant found for sessionId={llmServiceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problem persists, contact support@freenetworkmontior.click",
                    false,
                    "llmServiceMessage"
                );
            }


            // Check if Runner is null
            if (session.Runner == null)
            {
                return await SetResultMessageAsync(
                    llmServiceObj,
                    "Error: The assistant has no running process",
                    false,
                    "llmServiceMessage"
                );
            }

            // Check if Runner is in starting state
            if (session.Runner.IsStateStarting)
            {
                return await SetResultMessageAsync(
                    llmServiceObj,
                    "Please wait, the assistant is starting...",
                    false,
                    "llmServiceMessage"
                );
            }

            // Check if Runner is in failed state
            if (session.Runner.IsStateFailed)
            {
                return await SetResultMessageAsync(
                    llmServiceObj,
                    "The Assistant is stopped. Try reloading or refreshing the page.",
                    false,
                    "llmServiceMessage"
                );
            }

            // Process input and get response
            await session.Runner.SendInputAndGetResponse(llmServiceObj);
            return new ResultObj()
            {
                Success = true,
                Message = $"Processed UserInput: {llmServiceObj.UserInput}",
            };
        }
        catch (Exception e)
        {
            string errorMessage = $"Error: Unable to SendInputAndGetResponse. Exception: {e.Message}";
            _logger.LogError(e, errorMessage);
            return await SetResultMessageAsync(
                llmServiceObj,
                errorMessage,
                false,
                "llmServiceMessage"
            );
        }
    }

    private async Task PublishToRabbitMQAsync(string queue, LLMServiceObj obj, bool checkSystem)
    {
        if (!checkSystem || !obj.IsSystemLlm)
        {
            await _rabbitRepo.PublishAsync<LLMServiceObj>(queue, obj);
        }
    }


    private async Task<ResultObj> SetResultMessageAsync(
       LLMServiceObj obj,
       string message,
       bool success,
       string rabbitQueue,
       bool checkSystem = false)
    {
        // Update the object properties
        obj.ResultMessage = message;
        obj.ResultSuccess = success;
        obj.LlmMessage = success
            ? MessageHelper.SuccessMessage(message)
            : MessageHelper.ErrorMessage(message);

        await PublishToRabbitMQAsync(rabbitQueue, obj, checkSystem);


        // Return a new ResultObj
        return new ResultObj
        {
            Message = obj.ResultMessage,
            Success = obj.ResultSuccess
        };
    }




    private int _load; // Tracks the total load across all sessions


    private async Task SafeRemoveRunnerProcess(Session? checkSession, string sessionId)
    {
        try { await checkSession?.Runner?.RemoveProcess(sessionId); }
        catch { /* Suppress errors */ }
    }


    public void EndSession(string sessionId)
    {
        _sessions.TryRemove(sessionId, out _);
    }
}


public enum ResponseState { Initial, AwaitingInput, FunctionCallProcessed, Completed }



public class Session
{
    public List<string> Responses { get; } = new List<string>();
    public ILLMRunner? Runner { get; set; }
    public HistoryDisplayName HistoryDisplayName { get; set; } = new HistoryDisplayName();
}
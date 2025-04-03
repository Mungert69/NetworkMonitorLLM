using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Generic;
using System.Linq;
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
    Task<ResultObj> RemoveAllSessionIdProcesses(LLMServiceObj llmServiceObj);
    Task<ResultObj> StopRequest(LLMServiceObj llmServiceObj);
    Task<ResultObj> SendInputAndGetResponse(LLMServiceObj serviceObj);
    Task Init();
}

public class LLMService : ILLMService
{
    private readonly ILogger _logger;
    private static readonly Dictionary<string, string> ServiceIdMap = new()
{
    {"monitor", "Monitor"},
    {"nmap", "Security"},
    {"meta", "Penetration"},
    {"cmdprocessor", "Cmd Processor"},
    {"search", "Search"},
    {"quantum", "Quantum"}
    // Add more mappings as needed
};
    private readonly IServiceProvider _serviceProvider;
    private readonly IRabbitRepo _rabbitRepo;
    private ILLMFactory _llmFactory;

    private MLParams _mlParams;
    private string _serviceID;
    private ConcurrentDictionary<string, Session> _sessions = new ConcurrentDictionary<string, Session>();

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
        _sessions = await _llmFactory.LoadAllSessionsAsync();
        _llmFactory.Sessions = _sessions;
    }

    private string GetDisplayName(string serviceId)
{
    return ServiceIdMap.TryGetValue(serviceId, out var displayName) 
        ? displayName 
        : serviceId;  // Fallback to original ID if not found
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
                    await SetResultMessageAsync(llmServiceObj, $"{llmServiceObj.LLMRunnerType} {_serviceID} not started as it is disabled.", true, "llmServiceMessage");
                    return llmServiceObj;
                }

                string extraMessage = llmServiceObj.LLMRunnerType == "TestLLM"
                    ? $" , this can take up to {_mlParams.LlmSystemPromptTimeout} seconds..."
                    : "";
                await SetResultMessageAsync(llmServiceObj, $"Starting {llmServiceObj.LLMRunnerType} {GetDisplayName(_serviceID)} Expert{extraMessage}", true, "llmServiceMessage", true);

                await runner.StartProcess(llmServiceObj);
                // Only add a new session if it does not exist
                if (checkSession == null)
                {
                    _sessions[llmServiceObj.SessionId] = new Session
                    {
                        Runner = runner,
                        FullSessionId = llmServiceObj.SessionId,
                        HistoryDisplayName = new HistoryDisplayName
                        {
                            StartUnixTime = llmServiceObj.GetClientStartUnixTime(),
                            SessionId = llmServiceObj.SessionId,
                            Name = "",
                            LlmType = llmServiceObj.LLMRunnerType,
                            UserId = llmServiceObj.UserInfo?.UserID!
                        }
                    };
                }
                else
                {
                    checkSession.Runner = runner;
                }
                //var responseServiceObj = new LLMServiceObj(serviceObj);
                //responseServiceObj.LlmMessage = $"<Assistant:> Hi I'm {runner.Type} how can I help you. \n\n";
                //responseServiceObj..ResultMessage = "Sending Success Output";
                //responseServiceObj..ResultSuccess = true;
                //await PublishToRabbitMQAsync("llmServiceMessage", responseServiceObj, false);

                //await SetResultMessageAsync(llmServiceObj, $"Success {runner.Type} {_serviceID} Assistant Started", true, "llmServiceMessage", true);
                if (_serviceID == "monitor") await SetResultMessageAsync(llmServiceObj, $"Hi i'm {runner.Type} your Network Monitor Assistant. How can I help you.", true, "llmServiceMessage", true);


            }
            else
            {
                //await SetResultMessageAsync(llmServiceObj, $"Info: {llmServiceObj.LLMRunnerType} {_serviceID} Assistant already running so it was not reloaded", true, "llmServiceMessage", true);
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


    public async Task<ResultObj> RemoveAllSessionIdProcesses(LLMServiceObj llmServiceObj)
    {
        if (string.IsNullOrEmpty(llmServiceObj.SessionId))
        {
            return await SetResultMessageAsync(
                llmServiceObj,
                "Error: SessionId is null or empty.",
                false,
                "llmServiceMessage"
            );
        }

        var sessionId = llmServiceObj.SessionId.Split('_')[0];
        var removeSessions = _sessions
            .Where(kvp => kvp.Key.StartsWith($"{sessionId}_"))
            .Select(kvp => kvp.Value)
            .ToList();

        if (removeSessions == null || removeSessions.Count == 0)
        {
            return await SetResultMessageAsync(
                llmServiceObj,
                $"Error: No sessions running for sessionId {sessionId}.",
                false,
                "llmServiceMessage"
            );
        }

        var success = true;
        var messageBuilder = new StringBuilder();

        foreach (var session in removeSessions)
        {
            var fullSessionId = session.FullSessionId;
            if (!_sessions.TryGetValue(fullSessionId, out var sessionToRemove))
            {
                continue;
            }

            if (sessionToRemove.Runner == null)
            {
                continue;
            }

            try
            {
                // Save the conversation history before removing the session
                await _llmFactory.SaveHistoryForSessionAsync(fullSessionId);

                sessionToRemove.Runner.LoadChanged -= _llmFactory.OnRunnerLoadChanged;
                await sessionToRemove.Runner.RemoveProcess(fullSessionId);
                sessionToRemove.Runner = null;

                messageBuilder.Append($" {sessionToRemove.HistoryDisplayName?.LlmType} ");
            }
            catch (Exception e)
            {
                success = false;
                messageBuilder.Append($" Error removing process for sessionId {fullSessionId}: {e.Message} ");
            }
        }

        if (success)
        {
            return await SetResultMessageAsync(
                llmServiceObj,
                $"Success: Removed sessions for {messageBuilder.ToString()}",
                success,
                "llmSessionMessage",
                true
            );
        }
        else
        {
            _logger.LogError(messageBuilder.ToString());
            return await SetResultMessageAsync(
                llmServiceObj,
                messageBuilder.ToString(),
                success,
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
            await session.Runner.StopRequest(llmServiceObj.SessionId);

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
                return new ResultObj() { Success = false, Message = "Empty SessionID" };

                /*return await SetResultMessageAsync(
                    llmServiceObj,
                    $"No Assistant found for sessionId={llmServiceObj.SessionId}. Try reloading the Assistant or refreshing the page. If the problem persists, contact support@freenetworkmontior.click",
                    false,
                    "llmServiceMessage"
                );*/
            }


            // Check if Runner is null
            if (session.Runner == null)
            {
                return await SetResultMessageAsync(
                    llmServiceObj,
                    $"Error: SessionId {llmServiceObj.SessionId} has no running process. Try starting a new chat.",
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


    private async Task SafeRemoveRunnerProcess(Session? checkSession, string sessionId)
    {
        try
        {
            if (checkSession != null && checkSession.Runner != null)
            {
                await checkSession.Runner.RemoveProcess(sessionId);
                checkSession.Runner = null;
            }
        }
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
    public string FullSessionId { get; set; } = "";
    public List<string> Responses { get; } = new List<string>();
    public ILLMRunner? Runner { get; set; }
    public HistoryDisplayName HistoryDisplayName { get; set; } = new HistoryDisplayName();
}

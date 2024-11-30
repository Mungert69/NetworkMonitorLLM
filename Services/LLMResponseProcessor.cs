using System;
using System.IO;
using System.Linq;
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

// LLMResponseProcessor.cs
public interface ILLMResponseProcessor
{
    Task ProcessLLMOutput(LLMServiceObj serviceObj);
    Task ProcessLLMOutputError(LLMServiceObj serviceObj);
    Task ProcessLLMOuputInChunks(LLMServiceObj serviceObj);
    Task ProcessFunctionCall(LLMServiceObj serviceObj);
    bool AreAllFunctionsProcessed(string messageId);
    void MarkFunctionAsProcessed(LLMServiceObj serviceObj);
    List<LLMServiceObj> GetProcessedFunctionCalls(string messageId);
    void ClearFunctionCallTracker(string messageId);
    Task ProcessEnd(LLMServiceObj serviceObj);
    Task UpdateTokensUsed(LLMServiceObj serviceObj);
    bool IsFunctionCallResponse(string input);
    bool IsManagedMultiFunc { get; set; }
    bool SendOutput { get; set; }
}

public class LLMResponseProcessor : ILLMResponseProcessor
{

    private IRabbitRepo _rabbitRepo;
    private bool _sendOutput = true;

    private bool _isManagedMultiFunc = false;

    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, LLMServiceObj>> _functionCallTracker = new();


    public bool SendOutput { get => _sendOutput; set => _sendOutput = value; }
    public bool IsManagedMultiFunc { get => _isManagedMultiFunc; set => _isManagedMultiFunc = value; }

    public LLMResponseProcessor(IRabbitRepo rabbitRepo)
    {

        _rabbitRepo = rabbitRepo;
    }

    public async Task ProcessLLMOutput(LLMServiceObj serviceObj)
    {
        //Console.WriteLine(serviceObj.LlmMessage);
        serviceObj.ResultMessage = "Sending Success Output";
        serviceObj.ResultSuccess = true;
        if (_sendOutput && !string.IsNullOrEmpty(serviceObj.LlmMessage)) await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceMessage", serviceObj);
        //return Task.CompletedTask;
    }

    public async Task ProcessLLMOutputError(LLMServiceObj serviceObj)
    {
        //Console.WriteLine(serviceObj.LlmMessage);
        serviceObj.ResultMessage = "Sending Fail Output";
        serviceObj.ResultSuccess = false;
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
            await Task.Delay(30); // Pause between sentences 
        }

    }



    public async Task ProcessEnd(LLMServiceObj serviceObj)
    {
        serviceObj.LlmMessage = MessageHelper.ErrorMessage(serviceObj.LlmMessage);
        serviceObj.ResultMessage = MessageHelper.ErrorMessage(serviceObj.LlmMessage);
        serviceObj.ResultSuccess = true;
        await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceTimeout", serviceObj);

        // Cleanup function calls related to this MessageID to avoid memory leaks
        _functionCallTracker.TryRemove(serviceObj.MessageID, out _);
    }

    public async Task UpdateTokensUsed(LLMServiceObj serviceObj)
    {
        serviceObj.ResultMessage = "Sending Tokens Used";
        serviceObj.ResultSuccess = true;
        await _rabbitRepo.PublishAsync<LLMServiceObj>("llmUpdateTokensUsed", serviceObj);
        //return Task.CompletedTask;
    }

    /* public async Task ProcessFunctionCall(LLMServiceObj serviceObj)
     {
         if (_sendOutput) await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceFunction", serviceObj);

     }*/
    public async Task ProcessFunctionCall(LLMServiceObj serviceObj)
    {
        // Assign a unique ID to the function call
        if (!_isManagedMultiFunc)
        {
            string functionCallId = GenerateFunctionCallId();
            serviceObj.FunctionCallId = functionCallId;
            var newServiceObj = new LLMServiceObj(serviceObj);

            // Thread-safe addition to the tracker based on MessageID
            var callDictionary = _functionCallTracker.GetOrAdd(newServiceObj.MessageID, _ => new ConcurrentDictionary<string, LLMServiceObj>());
            callDictionary[functionCallId] = newServiceObj;
        }
        serviceObj.ResultMessage = "Sending Function call response";
        serviceObj.ResultSuccess = true;
        if (_sendOutput)
            await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceFunction", serviceObj);
    }

    public static string GenerateFunctionCallId()
{
    // Generate a random numeric component
    var random = new Random();
    int randomNumber = random.Next(10000000, 99999999); // 8-digit number
    return $"call_{randomNumber}";
}

    public void MarkFunctionAsProcessed(LLMServiceObj serviceObj)
    {
        if (_functionCallTracker.TryGetValue(serviceObj.MessageID, out var calls))
        {
            // Set IsProcessed to true for this function call in the tracker
            if (calls.TryGetValue(serviceObj.FunctionCallId, out var trackedServiceObj))
            {
                trackedServiceObj.IsProcessed = true;
                trackedServiceObj.UserInput = serviceObj.UserInput;
                trackedServiceObj.IsFunctionCallResponse = true;
                trackedServiceObj.IsFunctionCall = false;
                trackedServiceObj.FunctionName = serviceObj.FunctionName;
            }
        }
    }
    public List<LLMServiceObj> GetProcessedFunctionCalls(string messageId)
    {
        if (_functionCallTracker.TryGetValue(messageId, out var calls))
        {
            return calls.Values.Where(call => call.IsProcessed).ToList();
        }
        return new List<LLMServiceObj>();
    }

    public void ClearFunctionCallTracker(string messageId)
    {

        _functionCallTracker.TryRemove(messageId, out _);

    }

    public bool AreAllFunctionsProcessed(string messageId)
    {
        if (_functionCallTracker.TryGetValue(messageId, out var calls))
        {
            // Check if all function calls associated with this messageId are marked as processed
            bool allProcessed = calls.Values.All(call => call.IsProcessed);
            return allProcessed;
        }
        return false;
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
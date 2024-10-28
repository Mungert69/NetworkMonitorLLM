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
    Task ProcessLLMOuputInChunks(LLMServiceObj serviceObj);
    Task ProcessFunctionCall(LLMServiceObj serviceObj);
    Task<bool> AreAllFunctionsProcessed(string messageId);
    Task ProcessEnd(LLMServiceObj serviceObj);
    Task UpdateTokensUsed(LLMServiceObj serviceObj);
    bool IsFunctionCallResponse(string input);
    bool SendOutput { get; set; }
}

public class LLMResponseProcessor : ILLMResponseProcessor
{

    private IRabbitRepo _rabbitRepo;
    private bool _sendOutput = true;

        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, LLMServiceObj>> _functionCallTracker = new();


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
        serviceObj.LlmMessage = MessageHelper.ErrorMessage(serviceObj.LlmMessage);
        await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceTimeout", serviceObj);
        
        // Cleanup function calls related to this MessageID to avoid memory leaks
        _functionCallTracker.TryRemove(serviceObj.MessageID, out _);
    }

    public async Task UpdateTokensUsed(LLMServiceObj serviceObj)
    {
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
        string functionCallId = Guid.NewGuid().ToString();
        serviceObj.FunctionCallId = functionCallId;

        // Thread-safe addition to the tracker based on MessageID
        var callDictionary = _functionCallTracker.GetOrAdd(serviceObj.MessageID, _ => new ConcurrentDictionary<string, LLMServiceObj>());
        callDictionary[functionCallId] = serviceObj;

        if (_sendOutput)
            await _rabbitRepo.PublishAsync<LLMServiceObj>("llmServiceFunction", serviceObj);
    }

   public async Task<bool> AreAllFunctionsProcessed(string messageId)
{
    if (_functionCallTracker.TryGetValue(messageId, out var calls))
    {
        // Use .Values to access all LLMServiceObj instances and check if all are processed
        return calls.Values.All(call => call.IsProcessed);
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
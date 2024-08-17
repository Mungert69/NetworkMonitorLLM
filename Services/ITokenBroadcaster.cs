using System;

using System.Threading.Tasks;
namespace NetworkMonitor.LLM.Services;
 public interface ITokenBroadcaster
    {
        event Func<object, string, Task> LineReceived;
        Task ReInit(string sessionId);
        Task BroadcastAsync(ProcessWrapper process, string sessionId, string userInput, bool isFunctionCallResponse, string sourceLlm, string destionationLlm, bool sendOutput);
    }
using System;
using NetworkMonitor.Objects.ServiceMessage;
using System.Threading.Tasks;
namespace NetworkMonitor.LLM.Services;
 public interface ITokenBroadcaster
    {
        //event Func<object, string, Task> LineReceived;
        Task ReInit(string sessionId);
        Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, bool sendOutput);
    }
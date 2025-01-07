using System;
using System.Text;
using NetworkMonitor.Objects.ServiceMessage;
using System.Threading.Tasks;
using NetworkMonitor.Objects;
namespace NetworkMonitor.LLM.Services;
 public interface ITokenBroadcaster
    {
        //event Func<object, string, Task> LineReceived;
        Task ReInit(string sessionId);
        StringBuilder AssistantMessage { get ;  }
        Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput, int countEOT,bool sendOutput);
    }
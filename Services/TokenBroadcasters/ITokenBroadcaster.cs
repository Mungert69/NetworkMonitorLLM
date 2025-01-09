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
        Task SetUp(LLMServiceObj serviceObj, bool sendOutput);
        StringBuilder AssistantMessage { get ; set; }
        Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput);
    }
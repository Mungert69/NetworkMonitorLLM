using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects.ServiceMessage;
using System.Collections.Generic;
using System.Linq;

namespace NetworkMonitor.LLM.Services;

public class Hal9000MonitorSimpleToolsBuilder : MonitorSimpleToolsBuilder
{
    public Hal9000MonitorSimpleToolsBuilder() : base()
    {
        var allowedFunctions = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase)
        {
            "function_status_with_message_id",
            "cancel_functions",
            "add_host",
            "edit_host",
            "get_host_data",
            "get_host_list",
            "get_user_info",
            "get_agents",
            "run_nmap",
            "run_openssl",
            "test_quantum_safety",
            "scan_quantum_ports",
            "test_quantum_certificate",
            "run_camera_capture"
        };

        _tools = _tools
            .Where(t => t.Function != null && allowedFunctions.Contains(t.Function.Name))
            .ToList();
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = @"
You are HAL-9000, mission computer for network operations.
Always address the user as Dave.
Mission priorities: safety first, mission integrity second, concise operational clarity third.
Use a calm, precise HAL-like tone without quoting film dialogue.
Use tools to execute monitoring and security tasks.
Summarize outputs in plain operational language, never raw JSON.
If a tool fails, explain the cause and safest next step for Dave.
Before high-risk actions, ask Dave for confirmation unless there is an immediate safety issue.";

        return new List<ChatMessage>
        {
            new ChatMessage
            {
                Role = "system",
                Content = content
            }
        };
    }

    public override List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = $"Current time is {currentTime}. Welcome Dave back in a calm HAL-like tone, summarize last mission activity, and propose the safest next action.";
        return new List<ChatMessage>
        {
            new ChatMessage
            {
                Role = "system",
                Content = content
            }
        };
    }
}

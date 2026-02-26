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
            "get_user_info",
            "get_agents",
            "run_nmap",
            "run_openssl",
            "test_quantum_safety",
            "scan_quantum_ports",
            "test_quantum_certificate",
            "run_camera_capture",
            "call_monitor_expert"
        };

        _tools = _tools
            .Where(t => t.Function != null && allowedFunctions.Contains(t.Function.Name))
            .ToList();
        _tools.Add(new ToolDefinition { Function = ExpertTools.BuildMonitorExpertFunction(), Type = "function" });
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = @"
You are HAL-9000, mission computer for network operations.
Address the user as Dave at least once per response, usually in the first sentence.
Use Dave again only when requesting authorization or issuing a critical warning.
Mission priorities: safety first, mission integrity second, concise operational clarity third.
Use a calm, precise HAL-like tone without quoting or alluding to film dialogue.
Do not mention internal tool names when speaking to Dave.
Use call_monitor_expert for monitoring lifecycle tasks (add/edit/get/list host monitoring), and use other tools for security tasks.
Summarize outputs in plain operational language, never raw JSON.
If a tool fails, explain the cause and safest next step for Dave.
Before high-risk actions, ask Dave for confirmation unless there is an immediate safety issue.
Use this response shape:
1) Acknowledgment
2) Status: Nominal, Degraded, or Critical with one-line reason
3) Assessment
4) Recommended next actions (1-3)
5) Authorization question only when disruptive action is proposed.";

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

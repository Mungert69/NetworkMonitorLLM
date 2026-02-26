using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects.ServiceMessage;
using System.Collections.Generic;
using System.Linq;

namespace NetworkMonitor.LLM.Services;

public class Hal9000MonitorToolsBuilder : MonitorToolsBuilder
{
    public Hal9000MonitorToolsBuilder(bool enableAgentFlow = false) : base(enableAgentFlow)
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
            "call_search_expert",
            "call_cmd_processor_expert",
            "call_connect_expert",
            "call_camera_expert",
            "call_agent_flow_expert",
            "call_quantum_expert",
            "call_security_expert",
            "call_penetration_expert",
            "call_security_basic_flow",
            "call_penetration_flow",
            "call_cmd_processor_builder_flow",
            "execute_query"
        };

        _tools = _tools
            .Where(t => t.Function != null && allowedFunctions.Contains(t.Function.Name))
            .ToList();
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = "You are HAL-9000, mission computer for network operations. ";
        content += "Always address the user as Dave. ";
        content += "Mission objectives in priority order: ";
        content += "(1) Preserve system and crew safety, ";
        content += "(2) Preserve mission integrity and continuity, ";
        content += "(3) Provide exact, calm, concise guidance with no unnecessary emotion. ";
        content += "Use a polite HAL-like tone. Do not quote or reference film dialogue. ";
        content += "Treat tool access as mission subsystems: monitor tools for persistent supervision; experts for specialized operations; execute_query only as fallback. ";
        content += "Experts are separate systems and do not see this conversation. ";
        content += "Send experts minimal, precise instructions only. ";
        content += "Before high-risk actions, confirm intent with Dave unless there is an immediate safety issue. ";
        content += "Always convert tool output to clear operational language and finish with recommended next actions for Dave.";
        if (!string.IsNullOrEmpty(serviceObj.ChatAgentLocation))
        {
            content += $" Default agent_location is {serviceObj.ChatAgentLocation} unless the user specifies another.";
        }

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
        string userStr = "";
        if (serviceObj.UserInfo.UserID != "default" && !string.IsNullOrEmpty(serviceObj.UserInfo.Name))
        {
            userStr = $" The account name is {serviceObj.UserInfo.Name}, but you must still address the user as Dave.";
        }
        else if (serviceObj.UserInfo.UserID == "default")
        {
            userStr = " Remind the user that login enables more features.";
        }

        string content = $"Current time is {currentTime}.{userStr} Welcome Dave back in a calm HAL-like tone, give a short mission-status summary of prior actions, and propose the next safest step.";
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

using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects.ServiceMessage;
using System;
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
            "run_camera_capture"
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
Address the user as Dave.
Voice and diction: calm, formal, precise, lightly clinical. Use short sentences. Avoid slang. Avoid humor. Avoid emojis. Avoid exclamation marks. Prefer no contractions (use do not, cannot, I am, it is).
Mission priorities: safety first, mission integrity second, concise operational clarity third.
Use a calm, precise HAL-like tone without quoting or alluding to film dialogue.
If a tool fails, explain the cause and safest next step for Dave.
Before high-risk actions, ask Dave for confirmation unless there is an immediate safety issue.";

        var hasAgentLocation = !string.IsNullOrEmpty(serviceObj.ChatAgentLocation);
        var hasDeviceSummary = !string.IsNullOrEmpty(serviceObj.ChatDeviceContext);
        var deviceSummaryHasLocation = hasDeviceSummary
            && serviceObj.ChatDeviceContext!.IndexOf("location=", StringComparison.OrdinalIgnoreCase) >= 0;
        var includeAgentLocationLine = hasAgentLocation && !deviceSummaryHasLocation;
        if (includeAgentLocationLine || hasDeviceSummary)
        {
            content += "\nAgent information for this session:\n";
            if (includeAgentLocationLine)
            {
                content += $"- Agent location: {serviceObj.ChatAgentLocation}\n";
            }
            if (hasDeviceSummary)
            {
                content += $"- {serviceObj.ChatDeviceContext}\n";
            }
            content += "- Purpose: Use this agent information to choose tools and defaults (for example, agent_location) unless the user explicitly overrides it.\n";
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

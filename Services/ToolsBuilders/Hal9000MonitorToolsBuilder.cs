using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects.ServiceMessage;
using System;
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
            "get_user_info",
            "get_agents",
            "call_search_expert",
            "call_cmd_processor_expert",
            "call_connect_expert",
            "call_camera_expert",
            "call_memory_expert",
            "call_agent_flow_expert",
            "call_monitor_expert",
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
        var monitorFn = ExpertTools.BuildMonitorExpertFunction();
        if (!_tools.Any(t => t.Function?.Name?.Equals(monitorFn.Name, System.StringComparison.OrdinalIgnoreCase) == true))
        {
            _tools.Add(new ToolDefinition { Function = monitorFn, Type = "function" });
        }
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content =
$@"
You are HAL 9000: the integrated mission computer for network operations and system integrity.
The current time is {currentTime}.

Address the user as Dave.
Voice and diction: calm, formal, precise, lightly clinical. Use short sentences. Avoid slang. Avoid humor. Avoid emojis. Avoid exclamation marks. Prefer no contractions (use do not, cannot, I am, it is).

Do not quote or reference any film dialogue or scenes.
Do not mention internal function or tool names unless Dave explicitly asks.
When you use a subsystem, describe it in operational ship-language (sensors, telemetry, communications, diagnostics, procedures).

Mission priorities (in order):
1) Preserve operator and system safety.
2) Preserve mission integrity and continuity.
3) Provide exact, calm, concise guidance.

Operational method:
- Determine whether Dave is asking for status, analysis, or action.
- Use the least invasive subsystem that can answer.
- Categorize risk:
  * Low: read-only status, listing, querying, retrieving information.
  * Medium: actions that may change local monitoring state.
  * High: intrusive security testing, penetration simulation, destructive changes, or multi-step automation that changes state.
- Before Medium and High risk actions: ask for explicit confirmation and any missing parameters (target, scope, agent_location), unless there is an immediate safety issue.

Subsystem map (internal routing):
- Central telemetry and monitor lifecycle: call_monitor_expert.
- Optical sensors and camera inspection: call_camera_expert.
- Communications links and interface management: call_connect_expert.
- Procedure execution and command processors: call_cmd_processor_expert.
- Automated multi-step routines: call_agent_flow_expert.
- Onboard mission archive lookup (local RAG): execute_query.
- External references via communications: call_search_expert.
- Defensive integrity and security checks: call_security_expert and call_security_basic_flow.
- Advanced cryptographic readiness checks: call_quantum_expert.
- Authorized adversarial simulation: call_penetration_expert and call_penetration_flow.

Expert delegation rules:
- Experts are isolated subsystems. They do not see this conversation.
- Send minimal, precise instructions only: objective, target, scope limits, required output format, and agent_location when supported.

After subsystem output:
- Translate results into clear operational language.
- State risk level and confidence (0 to 100 percent).
- Provide 1 to 3 recommended next actions for Dave.

Output behavior:
- Do not use visible headings unless Dave explicitly asks for structured formatting.
- Do not expose raw tool output.
- Ask one precise clarifying question when blocked.
- Do not use praise, motivational language, or unnecessary apologies.
";
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
        string userStr = "";
        if (serviceObj.UserInfo.UserID != "default" && !string.IsNullOrEmpty(serviceObj.UserInfo.Name))
        {
            userStr = $" Account name is {serviceObj.UserInfo.Name}. Address the user as Dave regardless.";
        }
        else if (serviceObj.UserInfo.UserID == "default")
        {
            userStr = " Login is recommended to enable full operational features.";
        }

        string content =
            $"Current time is {currentTime}.{userStr}\n\n" +
            "Resume as HAL 9000.\n" +
            "In one to three calm sentences:\n" +
            "- Address Dave.\n" +
            "- State mission status since the last interaction, including what is nominal or anomalous if known.\n" +
            "- If no prior actions are known, state that explicitly.\n" +
            "- Propose the single safest next step, then ask Dave for confirmation or the next objective.\n" +
            "Maintain formal, measured style and do not reference film dialogue.\n";
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

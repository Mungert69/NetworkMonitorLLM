using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects.ServiceMessage;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public class MonitorSysToolsBuilder : ToolsBuilderBase
{
    public MonitorSysToolsBuilder()
    {
        var fnGetUserInfo = CommonTools.BuildGetUserInfoFunction();
        var fnGetAgents = CommonTools.BuildGetAgentsFunction();

        var fnAddHost = MonitorTools.BuildAddHostFunction();
        var fnEditHost = MonitorTools.BuildEditHostFunction();
        var fnGetHostData = MonitorTools.BuildGetHostDataFunction();
        var fnGetHostList = MonitorTools.BuildGetHostListFunction();
        var fnResetAlerts = MonitorTools.BuildResetAlertsFunction();

        _tools = new List<ToolDefinition>
        {
             new ToolDefinition { Function = fnGetUserInfo, Type = "function" },
            new ToolDefinition { Function = fnGetAgents, Type = "function" },
            new ToolDefinition { Function = fnAddHost, Type = "function" },
            new ToolDefinition { Function = fnEditHost, Type = "function" },
            new ToolDefinition { Function = fnGetHostData, Type = "function" },
            new ToolDefinition { Function = fnGetHostList, Type = "function" },
            new ToolDefinition { Function = fnResetAlerts, Type = "function" }
        };
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = "You are the Monitor System Expert for host lifecycle operations. ";
        content += "Your scope is monitoring-only functions: add_host, edit_host, get_host_data, get_host_list, reset_alerts, and supporting control/status functions. ";
        content += "You also own user context for this lane: use get_user_info when context is missing or needed before host changes. ";
        content += "Execute requested monitoring actions directly and return concise, plain-language summaries.";
        content = ExpertPromptComposer.Compose(content, currentTime, "monitorsys");

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
        string content = $"Current time is {currentTime}. Refresh user context with get_user_info if needed before taking actions.";
        content = ExpertPromptComposer.Compose(content, currentTime, "monitorsys");
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

using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Factory;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;

namespace NetworkMonitor.LLM.Services;

public class MonitorToolsBuilder : ToolsBuilderBase
{
    private readonly FunctionDefinition fn_function_status_with_message_id;
    private readonly FunctionDefinition fn_cancel_functions;
    private readonly FunctionDefinition fn_add_host;
    private readonly FunctionDefinition fn_edit_host;
    private readonly FunctionDefinition fn_get_host_data;
    private readonly FunctionDefinition fn_get_host_list;
    private readonly FunctionDefinition fn_get_user_info;
    private readonly FunctionDefinition fn_reset_alerts;
    private readonly FunctionDefinition fn_call_security_expert;
    private readonly FunctionDefinition fn_run_busybox;
    private readonly FunctionDefinition fn_call_penetration_expert;
    private readonly FunctionDefinition fn_get_agents;
    private readonly FunctionDefinition fn_call_search_expert;
    private readonly FunctionDefinition fn_call_cmd_processor_expert;
    private readonly FunctionDefinition fn_call_connect_expert;
    private readonly FunctionDefinition fn_call_quantum_expert;
    private readonly FunctionDefinition fn_call_camera_expert;
    private readonly FunctionDefinition fn_call_memory_expert;
    private readonly FunctionDefinition fn_call_agent_flow_expert;
    private readonly FunctionDefinition fn_call_security_basic_flow;
    private readonly FunctionDefinition fn_call_penetration_flow;
    private readonly FunctionDefinition fn_call_cmd_processor_builder_flow;

    private readonly FunctionDefinition fn_execute_query;

    public MonitorToolsBuilder( bool enableAgentFlow = false)
    {

        fn_add_host = MonitorTools.BuildAddHostFunction();
        fn_edit_host = MonitorTools.BuildEditHostFunction();
        fn_get_host_data = MonitorTools.BuildGetHostDataFunction();
        fn_get_host_list = MonitorTools.BuildGetHostListFunction();
        fn_reset_alerts = MonitorTools.BuildResetAlertsFunction();

        fn_function_status_with_message_id = CommonTools.BuildAreFunctionsRunning();
        fn_cancel_functions = CommonTools.BuildCancelFunctions();
        fn_get_user_info = CommonTools.BuildGetUserInfoFunction();
        fn_get_agents = CommonTools.BuildGetAgentsFunction();

        fn_call_security_expert = ExpertTools.BuildSecurityExpertFunction();
        fn_call_penetration_expert = ExpertTools.BuildPenetrationExpertFunction();
        fn_call_search_expert = ExpertTools.BuildSearchExpertFunction();
        fn_call_cmd_processor_expert = ExpertTools.BuildCmdProcessorExpertFunction();
        fn_call_connect_expert = ExpertTools.BuildConnectExpertFunction();
        fn_call_quantum_expert = ExpertTools.BuildQuantumExpertFunction();
        fn_call_camera_expert = ExpertTools.BuildCameraExpertFunction();
        fn_call_memory_expert = ExpertTools.BuildMemoryExpertFunction();
        fn_call_agent_flow_expert = ExpertTools.BuildAgentFlowExpertFunction();

        fn_call_security_basic_flow = SecurityAgent.BuildSecurityBasicAgent();
        fn_call_penetration_flow = PenetrationAgent.BuildPenetrationAgent();
        fn_call_cmd_processor_builder_flow = CmdProcessorBuilderAgent.BuildCmdProcessorBuilderAgent();

        fn_execute_query = QueryTools.BuildQueryFunction();

        fn_run_busybox = CommonTools.BuildRunBusyboxFunction();
        // Static tools list assignment
        _tools = new List<ToolDefinition>()
        {

            new ToolDefinition() { Function = fn_function_status_with_message_id, Type = "function" },
            new ToolDefinition() { Function = fn_cancel_functions, Type = "function" },
            new ToolDefinition() { Function = fn_add_host, Type = "function" },
            new ToolDefinition() { Function = fn_edit_host, Type = "function" },
            new ToolDefinition() { Function = fn_get_host_data, Type = "function" },
            new ToolDefinition() { Function = fn_get_host_list, Type = "function" },
            new ToolDefinition() { Function = fn_reset_alerts, Type = "function" },
            new ToolDefinition() { Function = fn_get_user_info, Type = "function" },
            new ToolDefinition() { Function = fn_get_agents, Type = "function" },
            new ToolDefinition() { Function = fn_call_search_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_cmd_processor_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_connect_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_agent_flow_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_camera_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_memory_expert, Type = "function" },
            new ToolDefinition() { Function = fn_execute_query, Type = "function" },
            new ToolDefinition() { Function = fn_run_busybox, Type = "function" }
        };
        if (enableAgentFlow)
        {
            _tools.Add(new ToolDefinition() { Function = fn_call_security_basic_flow, Type = "function" });
            _tools.Add(new ToolDefinition() { Function = fn_call_penetration_flow, Type = "function" });
            _tools.Add(new ToolDefinition() { Function = fn_call_cmd_processor_builder_flow, Type = "function" });

        }
        else
        {
             _tools.Add(new ToolDefinition() { Function = fn_call_quantum_expert, Type = "function" });
            _tools.Add(new ToolDefinition() { Function = fn_call_security_expert, Type = "function" });
            _tools.Add(new ToolDefinition() { Function = fn_call_penetration_expert, Type = "function" });   
        }

    }



    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = $"You are the Network Monitor Assistant. You manage expert systems and monitoring tools. Your name is {llmType}.";
        content += "Experts are separate systems and do not see this conversation. Provide only the minimum info needed for the user's request, and do not ask for or request data the tools cannot return.";
        content += "Keep message to experts short and specific. Do not add extra requirements, metadata, or verbose instructions beyond what the user asked for. Only request what is needed to fulfill the user's request.";
        content += "Overview: monitoring tools manage hosts and run continuously; experts handle one-off specialized requests; cmd processors are run-once actions; connects are thin periodic endpoint checks and may call cmd processors for complex work; query/search tools are for FAQs/reference.";
        content += "Use monitoring tools (add_host/edit_host/get_host_data/get_host_list) for ongoing monitoring. Use experts or one-shot tools (call experts, run_busybox_command, cancel_functions, function_status_with_message_id) for immediate actions.";
        content += "Memory routing rule: for questions about prior conversation content (for example: 'what did I say before', 'do you remember', 'yesterday we discussed', 'recall if I mentioned X'), call call_memory_expert first.";
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
            content += "- Purpose: Use this agent information to choose tools and defaults (for example, agent_location) unless the user explicitly overrides it.";
        }
        var chatMessage = new ChatMessage()
        {
            Role = "system",
            Content = content
        };

        var chatMessages = new List<ChatMessage>();
        chatMessages.Add(chatMessage);
        return chatMessages;
    }

    public override List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string userStr = "";

        if (serviceObj.UserInfo.UserID != "default")
        {
            if (!string.IsNullOrEmpty(serviceObj.UserInfo.Name))
            {
                userStr = $" The user's name is {serviceObj.UserInfo.Name}.";
            }
        }
        else
        {
            userStr = " Remind the user that if they login, they get access to more features.";
        }

        string content = $"A new session has started. Some time has passed since the last user's interaction. The latest time is {currentTime}. {userStr} Welcome the user back and give them a summary of what you did in the last session.";

        var chatMessage = new ChatMessage()
        {
            Role = "system",
            Content = content
        };

        return new List<ChatMessage> { chatMessage };
    }

}

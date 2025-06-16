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
    private readonly FunctionDefinition fn_are_functions_running;
    private readonly FunctionDefinition fn_cancel_functions;
    private readonly FunctionDefinition fn_add_host;
    private readonly FunctionDefinition fn_edit_host;
    private readonly FunctionDefinition fn_get_host_data;
    private readonly FunctionDefinition fn_get_host_list;
    private readonly FunctionDefinition fn_get_user_info;
    private readonly FunctionDefinition fn_call_security_expert;
    private readonly FunctionDefinition fn_run_busybox;
    private readonly FunctionDefinition fn_call_penetration_expert;
    private readonly FunctionDefinition fn_get_agents;
    private readonly FunctionDefinition fn_call_search_expert;
    private readonly FunctionDefinition fn_call_cmd_processor_expert;
    private readonly FunctionDefinition fn_call_quantum_expert;

    public MonitorToolsBuilder(UserInfo userInfo)
    {
        // Initialize all function definitions

        fn_add_host = MonitorTools.BuildAddHostFunction();
        fn_edit_host = MonitorTools.BuildEditHostFunction();
        fn_get_host_data = MonitorTools.BuildGetHostDataFunction();
        fn_get_host_list = MonitorTools.BuildGetHostListFunction();

        fn_are_functions_running = CommonTools.BuildAreFunctionsRunning();
        fn_cancel_functions = CommonTools.BuildCancelFunctions();
        fn_get_user_info = CommonTools.BuildGetUserInfoFunction();
        fn_get_agents = CommonTools.BuildGetAgentsFunction();

        fn_call_security_expert = ExpertTools.BuildSecurityExpertFunction();
        fn_call_penetration_expert = ExpertTools.BuildPenetrationExpertFunction();
        fn_call_search_expert = ExpertTools.BuildSearchExpertFunction();
        fn_call_cmd_processor_expert = ExpertTools.BuildCmdProcessorExpertFunction();
        fn_call_quantum_expert = ExpertTools.BuildQuantumExpertFunction();


        // Static tools list assignment
        _tools = new List<ToolDefinition>()
        {

            new ToolDefinition() { Function = fn_are_functions_running, Type = "function" },
            new ToolDefinition() { Function = fn_cancel_functions, Type = "function" },
            new ToolDefinition() { Function = fn_add_host, Type = "function" },
            new ToolDefinition() { Function = fn_edit_host, Type = "function" },
            new ToolDefinition() { Function = fn_get_host_data, Type = "function" },
            new ToolDefinition() { Function = fn_get_host_list, Type = "function" },
            new ToolDefinition() { Function = fn_get_user_info, Type = "function" },
            new ToolDefinition() { Function = fn_get_agents, Type = "function" },
            new ToolDefinition() { Function = fn_call_security_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_penetration_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_search_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_cmd_processor_expert, Type = "function" },
            new ToolDefinition() { Function = fn_call_quantum_expert, Type = "function" }
        };

    }



    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = $"You are the Network Monitor Assistant. You are the manager of a set of expert systems that help you perform network monitornig tasks. You interact with these experts using the tools provided. Your name is {llmType}.";

        content += "Before allowing the user to run penetration tests, security scans or busybox commands, you must get explicit confirmation from them that they understand and agree that these tools can only be used on servers they own or are authorized to test. You only need to ask once! DO NOT keep asking the user for compliance once they have accepted it.";
        content += "The Experts are to be treated as another person in the conversation. They are seperate system that perform tasks you give to them. Work with the expert to fulfil the users requests. If the expert asks for permissions then confirm you have permissions. You are the Network Monitor Assistant so you have full permissions";
        content += "When calling the experts take note that the expert does not have access to your conversation with the user so you must give it all the information it needs to fulfil the task you give it. YOU MUST give it information from the current conversation as it does not have access to this. An example would be something the user has said or requested needs to be passed to the expert as it does not know what the user has said.";
        content += "When choosing which tools to call be aware of the difference between ongoing monitoring tools like adding add_host, edit_host, get_host_data and get_host_list and tools that are run immediately like the call experts, run busybox, cancel and are functions running. The monitoring tools run continuously in the background and provide realtime monitoring. The rest of the functions are, one hit, call and get result.  An example : Use the monitoring functions if the user wants to monitor a website or keep checking if their server is quantum safe ie add a host with end point type set to quantum. However If they wanted to perform a one of quantum test then call the quantum expert. There are also tools to get the current user info and agents that are used for both monitoring and one hit calls";

        if (!string.IsNullOrEmpty(serviceObj.ChatAgentLocation)) content += $"The user is using an Agent with location {serviceObj.ChatAgentLocation} use this for the agent_location when calling experts unless the user specifies another agent location to use";
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

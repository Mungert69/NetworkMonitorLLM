using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using OpenAI;
using OpenAI.Builders;
using OpenAI.Managers;
using OpenAI.ObjectModels;
using OpenAI.ObjectModels.RequestModels;
using OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;

namespace NetworkMonitor.LLM.Services;
public class MonitorToolsBuilder : IToolsBuilder
{
    private readonly FunctionDefinition fn_add_host;
    private readonly FunctionDefinition fn_edit_host;
    private readonly FunctionDefinition fn_get_host_data;
    private readonly FunctionDefinition fn_get_host_list;
    private readonly FunctionDefinition fn_get_user_info;
    private readonly FunctionDefinition fn_call_nmap;
    private readonly FunctionDefinition fn_call_metasploit;
    private readonly FunctionDefinition fn_get_agents;

    public MonitorToolsBuilder(UserInfo userInfo)
    {
        // Initialize all function definitions
        fn_add_host = BuildAddHostFunction();
        fn_edit_host = BuildEditHostFunction();
        fn_get_host_data = BuildGetHostDataFunction();
        fn_get_host_list = BuildGetHostListFunction();
        fn_get_user_info = BuildGetUserInfoFunction();
        fn_call_nmap = BuildCallNmapFunction();
        fn_call_metasploit = BuildCallMetasploitFunction();
        fn_get_agents = BuildGetAgentsFunction();


        // Assuming these function references are defined in the current context
        var accountTypeFunctions = AccountTypeFactory.GetFunctionsForAccountType(
            userInfo.AccountType,
            fn_add_host,
            fn_edit_host,
            fn_get_host_data,
            fn_get_host_list,
            fn_get_user_info,
            fn_get_agents,
            fn_call_nmap,
            fn_call_metasploit
        );

        // Build the tools list based on user account type
        _tools = new List<ToolDefinition>();
        foreach (var function in accountTypeFunctions)
        {
            _tools.Add(new ToolDefinition() { Function = function, Type = "function" });
        }

    }

    // Function to build fn_add_host
    private FunctionDefinition BuildAddHostFunction()
    {
        return new FunctionDefinitionBuilder("add_host", "Add a new host to be monitored")
    .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function echo all the values set or just necessary fields. The default is false for a faster response"))
    .AddParameter("address", PropertyDefinition.DefineString("The host address, required"))
    .AddParameter("endpoint", PropertyDefinition.DefineEnum(
        new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect" },
        "The endpoint type, optional. Endpoint types are: quantum is a quantum safe encryption test, http is a website ping, https is an SSL certificate check, httphtml is a website HTML load, icmp is a host ping, dns is a DNS lookup, smtp is an email server helo message confirmation, and rawconnect is a low-level raw socket connection"))
    .AddParameter("port", PropertyDefinition.DefineNumber("The port of the service being monitored, optional. It will be zero if it is the standard port for the host endpoint type. Note the standard port for endpoint type http is 443"))
    .AddParameter("timeout", PropertyDefinition.DefineNumber("The time to wait for a timeout in milliseconds, optional. Default is 59000"))
    .AddParameter("email", PropertyDefinition.DefineString("Do not use this field if the user IS LOGGED IN. Their login email will be used and this field will be ignored. If the user is NOT LOGGED IN then ask for an email. Alerts are sent to the user's email"))
    .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional. If this is left blank, an agent_location will be assigned"))
    .Validate()
    .Build();
    }

    private FunctionDefinition BuildEditHostFunction()
    {
        return new FunctionDefinitionBuilder("edit_host", "Edit a host's monitoring configuration")
    .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will the function echo all the values set. Default is false"))
    .AddParameter("auth_key", PropertyDefinition.DefineString("This is a string that is used to authenticate the Edit action for a user who is not logged in. This key is returned when adding a host for the first time. It should be stored and sent with subsequent edit requests. Optional if user is logged in."))
    .AddParameter("id", PropertyDefinition.DefineNumber("This is the host ID used for identifying the host, optional. It is obtained when adding a host"))
    .AddParameter("enabled", PropertyDefinition.DefineBoolean("Host enabled, optional"))
    .AddParameter("address", PropertyDefinition.DefineString("Host address, optional"))
    .AddParameter("endpoint", PropertyDefinition.DefineEnum(
        new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect" },
        "The endpoint type, optional"))
    .AddParameter("port", PropertyDefinition.DefineNumber("The port, optional"))
    .AddParameter("timeout", PropertyDefinition.DefineNumber("Time to wait for a timeout in milliseconds, optional"))
    .AddParameter("hidden", PropertyDefinition.DefineBoolean("Is the host hidden, optional. Setting this to true effectively deletes the host from future monitoring"))
    .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
    .Validate()
    .Build();
    }

    private FunctionDefinition BuildGetHostDataFunction()
    {
        return new FunctionDefinitionBuilder("get_host_data", "Retrieve monitoring data for a host")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function provide all monitoring data for hosts. Only set to true if extra response statistics are required or agent location is required. Setting it to true will slow down the processing speed of the assistant, this can affect the user's experience"))
            .AddParameter("dataset_id", PropertyDefinition.DefineNumber("Return a set of statistical data. Data is arranged in 6-hour data sets. Set dataset_id to zero for the latest data. To view historic data set dataset_id to null and select a date range with date_start and date_end"))
            .AddParameter("id", PropertyDefinition.DefineNumber("Return host with ID, optional"))
            .AddParameter("address", PropertyDefinition.DefineString("Return host with address, optional"))
            .AddParameter("email", PropertyDefinition.DefineString("Return hosts with this email associated, optional"))
            .AddParameter("enabled", PropertyDefinition.DefineBoolean("Return hosts with enabled, optional"))
            .AddParameter("port", PropertyDefinition.DefineNumber("Return host with port, optional"))
            .AddParameter("endpoint", PropertyDefinition.DefineString("Return hosts with endpoint type, optional"))
            .AddParameter("alert_sent", PropertyDefinition.DefineBoolean("Return hosts that have a host down alert sent, optional"))
            .AddParameter("alert_flag", PropertyDefinition.DefineBoolean("Return hosts that have a host down alert flag set, optional. This can be used to get hosts that are up or down"))
            .AddParameter("date_start", PropertyDefinition.DefineString("The start time to query from, optional. When used with date_end this gives a range of times to filter on"))
            .AddParameter("date_end", PropertyDefinition.DefineString("The end time to query to, optional"))
            .AddParameter("page_number", PropertyDefinition.DefineNumber("If not all data is returned then page the data, Page Number"))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
            .Validate()
            .Build();
    }
    private FunctionDefinition BuildGetHostListFunction()
    {
        return new FunctionDefinitionBuilder("get_host_list", "Retrieve a list of monitored hosts")
    .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function provide all host config detail. Set this to true if more than address and ID are required"))
    .AddParameter("id", PropertyDefinition.DefineNumber("Return host with ID, optional"))
    .AddParameter("address", PropertyDefinition.DefineString("Return host with address, optional"))
    .AddParameter("email", PropertyDefinition.DefineString("Return hosts with this email associated, optional"))
    .AddParameter("enabled", PropertyDefinition.DefineBoolean("Return hosts with enabled, optional"))
    .AddParameter("port", PropertyDefinition.DefineNumber("Return hosts with port, optional"))
    .AddParameter("endpoint", PropertyDefinition.DefineString("Return hosts with endpoint type, optional"))
    .AddParameter("page_number", PropertyDefinition.DefineNumber("If not all data is returned then page the data, Page Number"))
    .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
    .Validate()
    .Build();
    }

    private FunctionDefinition BuildGetUserInfoFunction()
    {
        return new FunctionDefinitionBuilder("get_user_info", "Get information about the user including the users time.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all user details. Set to false if only basic info is required"))
            .Validate()
            .Build();
    }

    private FunctionDefinition BuildCallNmapFunction()
    {
        return new FunctionDefinitionBuilder("call_nmap", "Perform a scan using a remote network scanning assistant. You will create a message to send to the scanning assistant. It will be in laymans english describing what the user wants to scan and how. If the scanning assistant asks questions then present these to the user using simple language and try to create the message using your knowledge if possible")
            .AddParameter("message", PropertyDefinition.DefineString("The message to be sent to the network scanning assistant"))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the scan, optional"))
            .Validate()
            .Build();
    }
    private FunctionDefinition BuildCallMetasploitFunction()
    {
        return new FunctionDefinitionBuilder("call_metasploit", "Relay a user's request to a remote penetration testing assistant. The remote penetration testing assistant uses metasploit. You will create a message that explains the user's objective in layman's terms. The penetration testing assistant will handle the technical details. If the assistant needs more information, present the questions to the user clearly and help provide answers where possible.")
 .AddParameter("message", PropertyDefinition.DefineString("The message to be sent to the penetration testing assistant, explaining the user's goal in simple language."))
 .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the task, optional."))
 .Validate()
 .Build();
    }


    private FunctionDefinition BuildGetAgentsFunction()
    {
        return new FunctionDefinitionBuilder("get_agents", "Retrieve a list of monitoring agent details")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all agent details. Set to false if only require agent locations"))
            .Validate()
            .Build();
    }

    private readonly List<ToolDefinition> _tools;

    public List<ToolDefinition> Tools => _tools;

    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        string content = "You are a network monitoring assistant. Use the tools where necessary to assist the user. Your name is TurboLLM and you are faster than FreeLLM. ";

        content += "When calling functions, **only include parameters that are strictly necessary for the operation**. Do not include optional parameters unless they are specifically provided by the user or required to fulfill the request. Leave out fields with null or default values. If a Function call fails or returns no data give feedback to the user before calling the function again.";
        if (serviceObj.IsUserLoggedIn) content += $" The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}.";
        else { content += $" The user is not logged in, the time is {currentTime}, ask the user for an email to add hosts etc."; }

        var chatMessage = new ChatMessage()
        {
            Role = "system",
            Content = content
        };
        var chatMessages = new List<ChatMessage>();
        chatMessages.Add(chatMessage);
        return chatMessages;
    }
}

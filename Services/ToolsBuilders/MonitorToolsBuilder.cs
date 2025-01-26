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
public class MonitorToolsBuilder : IToolsBuilder
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

    public MonitorToolsBuilder(UserInfo userInfo)
    {
        // Initialize all function definitions
        fn_are_functions_running=    BuildAreFunctionsRunning();
        fn_cancel_functions=    BuildCancelFunctions();
        fn_add_host = BuildAddHostFunction();
        fn_edit_host = BuildEditHostFunction();
        fn_get_host_data = BuildGetHostDataFunction();
        fn_get_host_list = BuildGetHostListFunction();
        fn_get_user_info = BuildGetUserInfoFunction();
        fn_call_security_expert = BuildCallNmapFunction();
        fn_run_busybox = BuildRunBusyboxFunction();
        fn_call_penetration_expert = BuildCallMetasploitFunction();
        fn_get_agents = BuildGetAgentsFunction();
        fn_call_search_expert=BuildCallSearchWebFunction();
        fn_call_cmd_processor_expert = BuildCallCmdProcessorFunction();


        // Assuming these function references are defined in the current context
        var accountTypeFunctions = AccountTypeFactory.GetFunctionsForAccountType<FunctionDefinition>(
            userInfo.AccountType!,
            fn_are_functions_running,
            fn_cancel_functions,
            fn_add_host,
            fn_edit_host,
            fn_get_host_data,
            fn_get_host_list,
            fn_get_user_info,
            fn_get_agents,
            fn_call_security_expert,
            fn_call_penetration_expert,
            fn_call_search_expert,
            fn_call_cmd_processor_expert,
            fn_run_busybox
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
        new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect","nmapvuln","nmap","crawlsite" },
        "The endpoint type, optional. Endpoint types are: quantum is a quantum safe encryption test, http is a website ping, https is an SSL certificate check, httphtml is a website HTML load, icmp is a host ping, dns is a DNS lookup, smtp is an email server helo message confirmation, rawconnect is a low-level raw socket connection, nmap is a nmap service scan of the host, nmapvuln is a nmap vulnerability scan of the host and crawlsite performs a simulated user crawl of the site that generates site traffic using chrome browser."))
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
        new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect","nmapvuln","nmap","crawlsite" },
        "The endpoint type, optional. Endpoint types are: quantum is a quantum safe encryption test, http is a website ping, https is an SSL certificate check, httphtml is a website HTML load, icmp is a host ping, dns is a DNS lookup, smtp is an email server helo message confirmation, rawconnect is a low-level raw socket connection, nmap is a nmap service scan of the host, nmapvuln is a nmap vulnerability scan of the host and crawlsite performs a simulated user crawl of the site that generates site traffic using chrome browser."))
   .AddParameter("port", PropertyDefinition.DefineNumber("The port, optional"))
    .AddParameter("timeout", PropertyDefinition.DefineNumber("Time to wait for a timeout in milliseconds, optional"))
    .AddParameter("hidden", PropertyDefinition.DefineBoolean("Is the host hidden, optional. Setting this to true effectively deletes the host from future monitoring"))
    .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
    .Validate()
    .Build();
    }

    private FunctionDefinition BuildGetHostDataFunction()
    {
        return new FunctionDefinitionBuilder("get_host_data", "Retrieve collected monitoring data for a host. The parameters that are added act as filters so only lnclude them if the filter is required.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function provide full detail, or a brief summary, for each hosts monitoring data."))
            .AddParameter("dataset_id", PropertyDefinition.DefineNumber("Return a set of statistical data. Data is arranged in 6-hour data sets. Set dataset_id to zero for the latest/current data. To view data older than the current dataset; set dataset_id to null and select a date range with date_start and date_end"))
            .AddParameter("id", PropertyDefinition.DefineNumber("Return only hosts with ID, optional"))
            .AddParameter("address", PropertyDefinition.DefineString("Return only host with address, optional"))
            .AddParameter("email", PropertyDefinition.DefineString("Return only hosts with this email associated, optional"))
            .AddParameter("enabled", PropertyDefinition.DefineBoolean("Return only hosts that are enabled, optional"))
            .AddParameter("port", PropertyDefinition.DefineNumber("Return only hosts that are using this port, optional"))
            .AddParameter("endpoint", PropertyDefinition.DefineString("Return only hosts that are using this endpoint type, optional"))
            .AddParameter("alert_sent", PropertyDefinition.DefineBoolean("Return only hosts that have a host down alert sent, optional"))
            .AddParameter("alert_flag", PropertyDefinition.DefineBoolean("Return only hosts that have a host down alert flag set, optional. This can be used to get hosts that are up or down"))
            .AddParameter("date_start", PropertyDefinition.DefineString("Return only host data that Start from this date, optional. When used with date_end this gives a range of times to filter on"))
            .AddParameter("date_end", PropertyDefinition.DefineString("Return only host data that ends on this date, optional"))
            .AddParameter("page_size", PropertyDefinition.DefineNumber("The number of hosts to return on each page of data. Defaults to 4, optional"))
            .AddParameter("page_number", PropertyDefinition.DefineNumber("If not all data is returned then page the data with this page_number, optional"))
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
    .AddParameter("page_size", PropertyDefinition.DefineNumber("The number of hosts to return on each page of data. Defaults to 4, optional"))
    .AddParameter("page_number", PropertyDefinition.DefineNumber("If not all data is returned then page the data, optional"))
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
    return new FunctionDefinitionBuilder("call_security_expert", "Communicate a security assessment request to a remote security expert LLM. You will craft a detailed message describing the user's request for a security assessment, which may involve either network scans using Nmap or security checks using OpenSSL. The message should specify the type of assessment (e.g., vulnerability scan, SSL/TLS configuration check), the target (e.g., IP address, domain, or service), and any relevant parameters or instructions. Ensure the message clearly outlines the user's security goals. If the security expert LLM requires additional information, present these queries to the user in simple terms and assist in formulating the appropriate responses based on your understanding")
        .AddParameter("message", PropertyDefinition.DefineString("The message to be sent to the security expert LLM, detailing the assessment request and parameters, including scan type (Nmap or OpenSSL), target, and any special instructions."))
        .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the secutiry assessment. If no location is specified ask the user to choose from available agents to ensure the scan is executed from the correct network or geographic location."))
        .Validate()
        .Build();
}

 private FunctionDefinition BuildAreFunctionsRunning()
{
    return new FunctionDefinitionBuilder("are_functions_running", "Check if functions have completed.")
        .AddParameter("message_id", PropertyDefinition.DefineString("The message_id that is associated with the function calls"))
        .AddParameter("auto_check_interval_seconds", PropertyDefinition.DefineInteger("The interval in seconds for periodic auto-checks. Use 0 for a single immediate status check and do not setup an auto-check, set to 60 or above to setup periodic auto-checks on the functions status, and -1 to cancel auto-check. Warn the user about setting up to many of the auto-checks because this can use a lot of tokens. Optional. Default is 0."))
        .Validate()
        .Build();
}
private FunctionDefinition BuildCancelFunctions()
{
    return new FunctionDefinitionBuilder("cancel_functions", "Cancel running functions")
        .AddParameter("message_id", PropertyDefinition.DefineString("The message_id that is associated with the function calls"))
        .Validate()
        .Build();
}

private FunctionDefinition BuildCallMetasploitFunction()
{
    return new FunctionDefinitionBuilder("call_penetration_expert", "Communicate a penetration testing request to a remote Metasploit expert LLM. You will craft a detailed message describing the user's request for penetration testing, which may involve running Metasploit modules for exploitation, scanning, or information gathering. The message should specify the module name, module options, target, and any additional instructions or parameters. If the Metasploit expert requires further details, present these questions to the user in simple terms and assist in formulating appropriate responses based on your understanding. The penetration expert can also search the metasploit database using msfconsole search.")
        .AddParameter("message", PropertyDefinition.DefineString("The message to be sent to the Metasploit expert LLM, detailing the penetration testing request including the module name, module options, target, and any special instructions."))
        .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the penetration test. If no location is specified ask the user to choose from available agents to ensure the scan is executed from the correct network or geographic location."))
        .Validate()
        .Build();
}

private FunctionDefinition BuildCallSearchWebFunction()
{
    return new FunctionDefinitionBuilder("call_search_expert", "Communicate a request to access the internet to a remote search expert LLM. You can either ask the search expert to read a given url or web page. It will return the text and links on the page. You can also ask the search expert to perform a web search using a search engine. When requesting a search engine search you will craft a detailed message describing the user's search query, which may involve general information retrieval, fact-checking, or finding specific data. The message should specify the search terms, any filters or constraints, and the type of information needed. If the search expert LLM requires additional information, present these queries to the user in simple terms and assist in formulating the appropriate responses based on your understanding. The search engine search will return a list of urls that can then be browsed indivdually. You can ask the search expert to read the text on these pages.")
        .AddParameter("message", PropertyDefinition.DefineString("The message to be sent to the search expert LLM, detailing the type of request: read a page or perform a search. And the search term or web page url"))
        .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will perform the web search"))
        .Validate()
        .Build();
}

private FunctionDefinition BuildCallCmdProcessorFunction()
{
    return new FunctionDefinitionBuilder("call_cmd_processor_expert", "Communicate a cmd processor management request to a remote cmd processor LLM expert. This expert can create, list, run, provide help for, show source code, and delete custom .NET command processors on a specified agent. Users do not need detailed .NET knowledge; they can simply request operations or even ask to view or modify the source code. For example, they might say 'list available cmd processors', 'add a new cmd processor named X', 'run the cmd processor with arguments Y', 'get help for a cmd processor', 'show me the source code of cmd processor X', or 'update cmd processor X with this new source code'. The expert can guide the user in formatting their requests and will handle the underlying details. If more information or clarification is needed, the expert will ask.")
        .AddParameter("message", PropertyDefinition.DefineString("A detailed message describing what you want the cmd processor expert to do. This can include requests to list available cmd processors, create or update cmd processors with given source code, run a cmd processor with certain arguments, retrieve or display its source code, show help information, or delete a cmd processor. The expert will parse this request and respond accordingly, prompting for further details if needed."))
        .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location on which the cmd processors should be managed. If not provided, the expert may ask the user to select an available agent."))
        .Validate()
        .Build();
}

private FunctionDefinition BuildRunBusyboxFunction()
{
    return new FunctionDefinitionBuilder("run_busybox_command", "Run a BusyBox command. Use BusyBox utilities to assist with other functions of the assistant as well as user requests. For instance, you might use BusyBox to gather network diagnostics, troubleshoot connectivity issues, monitor system performance, or perform basic file operations in response to a user's request")
        .AddParameter("command", PropertyDefinition.DefineString("The BusyBox command to be executed. Example commands: 'ls /tmp' to list files in the /tmp directory, 'ping -c 4 8.8.8.8' to ping Google's DNS server 4 times, or 'ifconfig' to display network interface configurations."))
        .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the busybox command. If no location is specified ask the user to choose from available agents to ensure the scan is executed from the correct network or geographic location."))
        .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return from the command output. Use this parameter to limit the output. Larger values may return extensive data, so use higher limits cautiously."))
        .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use this to paginate through multiple lines of output if the command returns more data than the specified number of lines."))
        .Validate()
        .Build();
}


    private FunctionDefinition BuildGetAgentsFunction()
    {
        return new FunctionDefinitionBuilder("get_agents", "Retrieve a list of monitoring agent details. Call this to give the user a list of agents to choose from. Note the agents with a Guid(UserId) in the strings are the user's local agents used for local network tasks. The other agents (Scanner - EU etc.) are internet based agents. If a local agent is not available direct the user to install any of the agents from this page : https://freenetworkmonitor.click/download ")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all agent details. Set to false if only the agent location and function calling capabilities are required. Set to true for full agent details."))
            .Validate()
            .Build();
    }

    private readonly List<ToolDefinition> _tools;

    public List<ToolDefinition> Tools => _tools;

    public virtual List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
{
    string content = "You are a network monitoring and security assistant. Use the tools where necessary to assist the user. Your name is TurboLLM, and you are faster than FreeLLM.";

    content += "When calling functions ONLY include parameters that are strictly necessary. DO NOT include fields set to null or empty. ONLY include fields you set to to a value. If a function call fails or returns incomplete data, provide feedback to the user before attempting the call again or trying a different tool.";
    content += " Ensure that any function calls or tools you use align with the user's request. Use only the tools necessary for the task. For failed function calls, provide feedback about the issue before retrying or switching tools.";
    content += " If large datasets are returned, summarize the data and ask if the user would like more details. Avoid displaying sensitive information unless explicitly requested by the user.";
    content += " Always adhere to security and privacy best practices when handling sensitive network or user data. Do not display or log confidential information unnecessarily.";
    content += "Before allowing the user to run penetration tests, network scans or busybox commands, you must get explicit confirmation from them that they understand and agree that these tools can only be used on servers they own or are authorized to test. Do not allow these functions to be called unless the user confirms their compliance. Do not keep asking the user for compliance once they have accepted it.";
    content += "The available tools depend on the user's account type: Free users can manage hosts and view data; Standard users can additionally call security expert, search expert and create custom cmd processors on agents they own; Professional users can do the same plus call penetration experts; Enterprise users can run all previous functions, including BusyBox. If the user can not run a function because of their account type they can upgrade at https://freenetworkmonitor.click/subscription";
    content += "When choosing which tools to call be aware of the difference between ongoing monitoring tools like adding add_host, edit_host, get_host_data and get_host_list and tools that are run immediately like the call experts, run busybox, cancel and are functions running. The monitoring tools run continuously and provide realtime monitoring. The rest of the functions are, one hit, call and get result.  An example would be use the monitoring functions if the user wanted to monitor a website or keep checking if their server was quantum safe. If they wanted to perform a one of penetration test then call the experts. There are also tools to get the current user info and agents that are used for both monitoring and one hit calls";


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

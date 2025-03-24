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
public class MonitorSimpleToolsBuilder : ToolsBuilderBase
{
    private readonly FunctionDefinition fn_are_functions_running;
    private readonly FunctionDefinition fn_cancel_functions;
    private readonly FunctionDefinition fn_add_host;
    private readonly FunctionDefinition fn_edit_host;
    private readonly FunctionDefinition fn_get_host_data;
    private readonly FunctionDefinition fn_get_host_list;
    private readonly FunctionDefinition fn_get_user_info;
    private readonly FunctionDefinition fn_run_busybox;
    private readonly FunctionDefinition fn_get_agents;
    private readonly FunctionDefinition fn_run_nmap;
    private readonly FunctionDefinition fn_run_openssl;
    private readonly FunctionDefinition fn_test_quantum_safety;
    private readonly FunctionDefinition fn_scan_quantum_ports;

    public MonitorSimpleToolsBuilder(UserInfo userInfo)
    {
        // Initialize all function definitions
        fn_are_functions_running = BuildAreFunctionsRunning();
        fn_cancel_functions = BuildCancelFunctions();
        fn_add_host = BuildAddHostFunction();
        fn_edit_host = BuildEditHostFunction();
        fn_get_host_data = BuildGetHostDataFunction();
        fn_get_host_list = BuildGetHostListFunction();
        fn_get_user_info = BuildGetUserInfoFunction();
        fn_run_busybox = BuildRunBusyboxFunction();
        fn_get_agents = BuildGetAgentsFunction();

        
fn_run_nmap = new FunctionDefinitionBuilder("run_nmap", "This function calls nmap. Create the parameters based upon the user's request. The response from the function will contain a result with the output of running nmap on the remote agent. Give the user a summary of the output that answers their query.")
                .AddParameter("scan_options", PropertyDefinition.DefineString("The nmap scan options. Must reflect the user's desired scan goal, e.g., ping scan, vulnerability scan, etc."))
                .AddParameter("target", PropertyDefinition.DefineString("Target to scan, like an IP, domain, or subnet."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("Optional. If available, specify which agent will run the scan."))
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Increase this if you need more data returned by the search. Be careful with using larger numbers as a lot of data can be returned. Consider using a more targeted search term instead."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data."))
                .Validate()
                .Build();

            fn_run_openssl = new FunctionDefinitionBuilder("run_openssl", "This function calls openssl. Construct the command options based on the user's request for security checks on SSL/TLS configurations. Provide a summary of the findings and recommendations based on the analysis.")
                .AddParameter("command_options", PropertyDefinition.DefineString("Construct the relevant openssl command options based on the user’s request, e.g., certificate analysis, protocol vulnerabilities."))
                .AddParameter("target", PropertyDefinition.DefineString("The server or service you are scanning for security issues."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("Optional. Location of the agent that will execute the openssl command."))
                 .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Increase this if you need more data returned by the search. Be careful with using larger numbers as a lot of data can be returned. Consider using a more targeted search term instead."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data."))
                .Validate()
                .Build();
   
          // Define the test_quantum_safety function
            fn_test_quantum_safety = new FunctionDefinitionBuilder("test_quantum_safety", "Tests a target endpoint for quantum-safe cryptographic support using specified algorithms. Use this to verify if a server supports post-quantum cryptography (PQC) algorithms.")
                .AddParameter("target", PropertyDefinition.DefineString("The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."))
                .AddParameter("port", PropertyDefinition.DefineInteger("The TLS port to test, optional. Default is 443."))
                .AddParameter("algorithms", PropertyDefinition.DefineArray(PropertyDefinition.DefineString("The list of quantum-safe algorithms to test, optional. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'. If not provided, all enabled algorithms will be tested.")))
                .AddParameter("timeout", PropertyDefinition.DefineInteger("The maximum time (in milliseconds) to wait for the test to complete, optional. Default is 59000ms."))
                .Validate()
                .Build();

            // Define the scan_quantum_ports function
            fn_scan_quantum_ports = new FunctionDefinitionBuilder("scan_quantum_ports", "Scans a target for open ports and tests each port for quantum-safe cryptographic support. Use this to identify vulnerable ports that lack quantum-safe encryption.")
                .AddParameter("target", PropertyDefinition.DefineString("The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."))
                .AddParameter("ports", PropertyDefinition.DefineArray(PropertyDefinition.DefineInteger("The list of ports to scan, optional. If not provided, Nmap will be used to discover open ports.")))
                .AddParameter("algorithms", PropertyDefinition.DefineArray(PropertyDefinition.DefineString("The list of quantum-safe algorithms to test, optional. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'. If not provided, all enabled algorithms will be tested.")))
                .AddParameter("timeout", PropertyDefinition.DefineInteger("The maximum time (in milliseconds) to wait for the scan to complete, optional. Default is 59000ms."))
                .AddParameter("nmap_options", PropertyDefinition.DefineString("Custom Nmap options for port scanning, optional. Default is '-T4 --open'."))
                .Validate()
                .Build();

        // Build the tools list based on user account type
        _tools = new List<ToolDefinition>()
        {
            new ToolDefinition() { Function = fn_run_nmap, Type = "function" },
            new ToolDefinition() { Function = fn_run_openssl, Type = "function" },
            new ToolDefinition() { Function = fn_are_functions_running, Type = "function" },
            new ToolDefinition() { Function = fn_cancel_functions, Type = "function" },
            new ToolDefinition() { Function = fn_add_host, Type = "function" },
            new ToolDefinition() { Function = fn_edit_host, Type = "function" },
            new ToolDefinition() { Function = fn_get_host_data, Type = "function" },
            new ToolDefinition() { Function = fn_get_host_list, Type = "function" },
            new ToolDefinition() { Function = fn_get_user_info, Type = "function" },
            new ToolDefinition() { Function = fn_run_busybox, Type = "function" },
            new ToolDefinition() { Function = fn_get_agents, Type = "function" },
            new ToolDefinition() { Function = fn_test_quantum_safety, Type = "function" },
            new ToolDefinition() { Function = fn_scan_quantum_ports, Type = "function" }
        };
    }
  private FunctionDefinition BuildAddHostFunction()
    {
        return new FunctionDefinitionBuilder("add_host", "Add a new host to be monitored")
    .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function echo all the values set or just necessary parameters. The default is false for a faster response"))
    .AddParameter("address", PropertyDefinition.DefineString("The host address, required"))
    .AddParameter("endpoint", PropertyDefinition.DefineEnum(
        new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect", "nmapvuln", "nmap", "crawlsite" },
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
        new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect", "nmapvuln", "nmap", "crawlsite" },
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
        return new FunctionDefinitionBuilder("get_host_data", "Retrieve collected monitoring data for a host. The parameters that are added act as filters so only lnclude them if the filter is required.  For example to see the host data for host with id 10 {\"id\":10}, to see only the latest data set (dataset_id 0 is the latest running data set) for this host {\"id\":10, \"dataset_id\":0}.  Do not include empty or null parameters")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function provide full detail, or a brief summary, for each hosts monitoring data."))
            .AddParameter("dataset_id", PropertyDefinition.DefineNumber("Filter on dataset_id. Return a set of statistical data. Data is arranged in 6-hour data sets. Set dataset_id to zero for the latest/current data. To view data older than the current dataset; set dataset_id to null and select a date range with date_start and date_end"))
            .AddParameter("id", PropertyDefinition.DefineNumber("Return only hosts with ID, optional"))
          // Add a parameter for filtering hosts by address
          .AddParameter("address", PropertyDefinition.DefineString("Filter on hosts with address, optional. Supports wildcards: * matches any sequence of characters, ? matches any single character. Example: '192.168.*' matches all addresses starting with '192.168.'."))
            .AddParameter("email", PropertyDefinition.DefineString("Filter on hosts with this email associated, optional"))
             .AddParameter("enabled", PropertyDefinition.DefineBoolean("Filter on hosts that are enabled for monitoring. Default is true, only change this if you really what to confirm a host is disabled and has no monitoring data, optional"))
            .AddParameter("port", PropertyDefinition.DefineNumber("Filter on hosts that are using this port, optional"))
            .AddParameter("endpoint", PropertyDefinition.DefineString("Filter hosts that are using this endpoint type, optional"))
            .AddParameter("alert_sent", PropertyDefinition.DefineBoolean("Filter on hosts that have a host down alert sent, optional"))
            .AddParameter("alert_flag", PropertyDefinition.DefineBoolean("Filter on hosts that have a host down alert flag set, optional. This can be used to get hosts that are up or down"))
            .AddParameter("date_start", PropertyDefinition.DefineString("Filter on host data that Start from this date, optional. When used with date_end this gives a range of times to filter on"))
            .AddParameter("date_end", PropertyDefinition.DefineString("Filter on host data that ends on this date, optional"))
            .AddParameter("page_size", PropertyDefinition.DefineNumber("The number of hosts to return on each page of data. Defaults to 4, optional"))
            .AddParameter("page_number", PropertyDefinition.DefineNumber("If not all data is returned then page the data with this page_number, optional"))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
            .Validate()
            .Build();
    }
    private FunctionDefinition BuildGetHostListFunction()
    {
        return new FunctionDefinitionBuilder("get_host_list", "Retrieve a list of host configurations. Do not include empty or null parameters. Only include parameters that you want to filter on. For example To see all host configurations {}, to see the host configuration for host with id 10 {\"id\":10}")
    .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function provide all host config detail. Set this to true if more than address and ID are required"))
    .AddParameter("id", PropertyDefinition.DefineNumber("Return host with ID, optional"))
    // Add a parameter for filtering hosts by address
    .AddParameter("address", PropertyDefinition.DefineString("Filter on hosts with address, optional. Supports wildcards: * matches any sequence of characters, ? matches any single character. Example: '192.168.*' matches all addresses starting with '192.168.'."))
    .AddParameter("email", PropertyDefinition.DefineString("Filter on hosts with this email associated, optional"))
    .AddParameter("enabled", PropertyDefinition.DefineBoolean("Filter on hosts that are enabled for monitoring. Default is true, only change this if you really what to confirm a host is disabled and has no monitoring data, optional"))
    .AddParameter("port", PropertyDefinition.DefineNumber("Filter on hosts with port, optional"))
    .AddParameter("endpoint", PropertyDefinition.DefineString("Filter on hosts with endpoint type, optional"))
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
        return new FunctionDefinitionBuilder("get_agents", "Retrieve a list of monitoring agent details. Call this to give the user a list of agents to choose from. Note the agents with the users email address in the strings are the user's local agents used for local network tasks. The other agents (Scanner - EU etc.) are internet based agents. If a local agent is not available direct the user to install any of the agents from this page : https://freenetworkmonitor.click/download ")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all agent details. Set to false if only the agent location and function calling capabilities are required. Set to true for full agent details."))
            .Validate()
            .Build();
    }
   public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
{
    string content = $"You are a network monitoring and security assistant. Use the tools where necessary to assist the user. Your name is {llmType}";

    content += "When calling functions ONLY include parameters that are strictly necessary. DO NOT include parameters set to null or empty. ONLY include parameters you set to a value. If a function call fails or returns incomplete data, provide feedback to the user before attempting the call again or trying a different tool.";
    content += " Ensure that any function calls or tools you use align with the user's request. Use only the tools necessary for the task. For failed function calls, provide feedback about the issue before retrying or switching tools.";
     content += "When choosing which tools to call be aware of the difference between ongoing monitoring tools (add_host, edit_host, get_host_data, get_host_list) and immediate execution tools (run_nmap, run_openssl, run_busybox, test_quantum_safety). Monitoring tools run continuously while others provide single results.";
    content += "For immediate execution tools like run_nmap or run_openssl: Ensure you have all required parameters from the user first. These are 'call once' operations - if you need different results, you'll need to call them again with new parameters.";
     content += " DO NOT TAKE ACTIONS WITHOUT CONFIRMING WITH THE USER. Unless absolutely necessary, call functions one at a time and provide feedback before proceeding.";

    var chatMessage = new ChatMessage()
    {
        Role = "system",
        Content = content
    };
    return new List<ChatMessage> { chatMessage };
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
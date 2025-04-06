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


        fn_run_nmap = new FunctionDefinitionBuilder(
            "run_nmap",
            "Executes an nmap network scan based on the user's request. " +
            "The function should be called when the user needs network discovery, port scanning, service detection, " +
            "vulnerability assessment, or other network reconnaissance tasks. " +
            "Construct appropriate scan options based on the user's specific needs (e.g., stealth scanning, " +
            "service version detection, OS fingerprinting). " +
            "After receiving results, analyze the output to provide the user with: " +
            "1) A concise summary of key findings, 2) Security implications, 3) Any recommended next steps. " +
            "Highlight critical vulnerabilities or unusual findings prominently.")
            .AddParameter(
                "scan_options",
                PropertyDefinition.DefineString(
                    "Nmap command-line options to execute. " +
                    "Should be constructed based on the user's specific request. " +
                    "Examples: '-sV' for service version detection, '-O' for OS fingerprinting, " +
                    "'-A' for aggressive scan, '-p-' for all ports, '--script vuln' for vulnerability scanning. " +
                    "Combine options as needed (e.g., '-sS -p 80,443 -T4'). " +
                    "Ensure options are valid and security-conscious (avoid overly aggressive scans without justification)."))
            .AddParameter(
                "target",
                PropertyDefinition.DefineString(
                    "The target to scan - can be an IP address (e.g., '192.168.1.1'), " +
                    "IP range ('192.168.1.0/24'), domain name ('example.com'), " +
                    "or hostname. Validate the target with the user if ambiguous."))
            .AddParameter(
                "agent_location",
                PropertyDefinition.DefineString(
                    "Optional. Preferred agent location if scanning from multiple possible locations. " +
                    "Important for scanning internal vs external networks. " +
                    "Example: 'us-east-1' for AWS region or 'corporate-dmz' for specific network segment."))
            .AddParameter(
                "number_lines",
                PropertyDefinition.DefineInteger(
                    "Limit for output lines to return. Default to 50 for initial scans. " +
                    "Increase for detailed analysis (e.g., 200-500 for full port scans), " +
                    "but be mindful of response size. Consider filtering results first."))
            .AddParameter(
                "page",
                PropertyDefinition.DefineInteger(
                    "Pagination control for large result sets. Start with 1. " +
                    "Increment to view additional portions of extensive scan results."))
            .Validate()
            .Build();

        fn_run_openssl = new FunctionDefinitionBuilder(
            "run_openssl",
            "Executes OpenSSL commands for security analysis of SSL/TLS configurations, certificates, " +
            "and cryptographic protocols. Use when the user requests: certificate inspection, " +
            "protocol support checks, cipher suite evaluation, or cryptographic vulnerability testing. " +
            "Analyze results to provide: 1) Security grade of configuration, 2) Specific vulnerabilities found, " +
            "3) Recommended fixes, 4) Compliance status with current best practices.")
            .AddParameter(
                "command_options",
                PropertyDefinition.DefineString(
                    "OpenSSL command and options constructed for the specific task. " +
                    "Examples: 's_client -connect example.com:443 -showcerts' for certificate analysis, " +
                    "'ciphers -v' to list supported ciphers, 'x509 -text -noout' for certificate details. " +
                    "Include all necessary flags for the requested analysis."))
            .AddParameter(
                "target",
                PropertyDefinition.DefineString(
                    "Target server in format 'host:port' (e.g., 'example.com:443'), " +
                    "or certificate file if analyzing local files. For SMTP/other protocols, " +
                    "use format 'smtp.example.com:25' with appropriate protocol options."))
            .AddParameter(
                "agent_location",
                PropertyDefinition.DefineString(
                    "Optional. Preferred agent location if testing from different network perspectives. " +
                    "Important for testing internal vs external services or geographic-specific configurations."))
            .AddParameter(
                "number_lines",
                PropertyDefinition.DefineInteger(
                    "Limit for output lines to return. Default to 100 for certificate analysis. " +
                    "May need higher values (300+) for verbose outputs like full certificate chains."))
            .AddParameter(
                "page",
                PropertyDefinition.DefineInteger(
                    "Pagination control for extensive outputs (e.g., multi-certificate chains). " +
                    "Start with 1, increment to view additional sections."))
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
        return new FunctionDefinitionBuilder(
            "add_host",
            "Add a new host to be monitored. Example: To monitor 'example.com' with HTTPS: {'address':'example.com','endpoint':'https'}. For vulnerability scans: {'address':'192.168.1.5','endpoint':'nmapvuln'}.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Return full configuration details. Default: false (faster response)."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "[REQUIRED] Host address (IP/domain). Examples: '10.0.0.1', 'app.prod'."))
        .AddParameter("endpoint", PropertyDefinition.DefineEnum(
            new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect", "nmapvuln", "nmap", "crawlsite" },
            "Monitoring type. quantum=quantum-safe encryption test, http=website ping, https=SSL check, httphtml=HTML load, icmp=host ping, dns=DNS lookup, smtp=email HELO, rawconnect=raw socket, nmapvuln=Nmap vuln scan, nmap=service scan, crawlsite=Chrome-based crawl. Default: 'https' if port 443."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "Service port. Default: Standard for endpoint (443 for HTTPS). Use 0 for auto-detection."))
        .AddParameter("timeout", PropertyDefinition.DefineNumber(
            "Timeout in milliseconds. Default: 59000 (~1 minute)."))
        .AddParameter("email", PropertyDefinition.DefineString(
            "[Non-logged-in users only] Alert email. Ignored if authenticated."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Monitoring agent (e.g., 'Scanner-EU'). Auto-assigned if blank."))
        .Validate()
        .Build();
    }

    private FunctionDefinition BuildEditHostFunction()
    {
        return new FunctionDefinitionBuilder(
            "edit_host",
            "Edit a host's monitoring configuration. Example: Disable host ID 15: {'id':15,'enabled':false}. Change to ICMP: {'address':'legacy-app','endpoint':'icmp'}.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Return full updated configuration. Default: false."))
        .AddParameter("auth_key", PropertyDefinition.DefineString(
            "[Required if not logged in] Auth key from initial host creation."))
        .AddParameter("id", PropertyDefinition.DefineNumber(
            "Host ID (from get_host_list). Example: 15."))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean(
            "Enable/disable monitoring. Default: true."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "Update host address (e.g., 'new-app.prod')."))
        .AddParameter("endpoint", PropertyDefinition.DefineEnum(
            new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect", "nmapvuln", "nmap", "crawlsite" },
            "Same options as add_host. Changes monitoring type."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "Update service port (e.g., 8080 for non-standard HTTP)."))
        .AddParameter("timeout", PropertyDefinition.DefineNumber(
            "Adjust timeout (ms). Default: 59000."))
        .AddParameter("hidden", PropertyDefinition.DefineBoolean(
            "Hide host (soft delete). Default: false."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Reassign monitoring agent (e.g., 'Scanner-US')."))
        .Validate()
        .Build();
    }

    private FunctionDefinition BuildGetHostDataFunction()
    {
        return new FunctionDefinitionBuilder(
            "get_host_data",
            "Retrieve monitoring data with filters. Example: Latest data for host ID 10: {'id':10,'dataset_id':0}. Find down hosts: {'alert_flag':true}.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Include full metrics (response times/headers). Default: false."))
        .AddParameter("dataset_id", PropertyDefinition.DefineNumber(
            "6-hour data window (0=latest). Use null + dates for history."))
        .AddParameter("id", PropertyDefinition.DefineNumber(
            "Host ID (e.g., 15)."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "Wildcard filter (e.g., '*.prod'). Supports * and ? wildcards."))
        .AddParameter("email", PropertyDefinition.DefineString(
            "Filter by alert recipient email."))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean(
            "Active/inactive hosts. Default: true."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "Filter by port (e.g., 443)."))
        .AddParameter("endpoint", PropertyDefinition.DefineString(
            "Filter by endpoint (e.g., 'https')."))
        .AddParameter("alert_sent", PropertyDefinition.DefineBoolean(
            "Hosts that triggered alerts."))
        .AddParameter("alert_flag", PropertyDefinition.DefineBoolean(
            "Hosts in alert state (up/down)."))
        .AddParameter("date_start", PropertyDefinition.DefineString(
            "ISO start time (e.g., '2024-05-01T00:00:00')."))
        .AddParameter("date_end", PropertyDefinition.DefineString(
            "ISO end time."))
        .AddParameter("page_size", PropertyDefinition.DefineNumber(
            "Results per page. Default: 4."))
        .AddParameter("page_number", PropertyDefinition.DefineNumber(
            "Pagination page. Default: 1."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Filter by agent (e.g., 'Scanner-EU')."))
        .Validate()
        .Build();
    }

    private FunctionDefinition BuildGetHostListFunction()
    {
        return new FunctionDefinitionBuilder(
            "get_host_list",
            "List monitored hosts. Example: All 192.168.* hosts: {'address':'192.168.*'}. Disabled hosts: {'enabled':false}.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Include full config (tags/thresholds). Default: false."))
        .AddParameter("id", PropertyDefinition.DefineNumber(
            "Host ID (e.g., 15)."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "Wildcard filter (e.g., 'prod-?.*')."))
        .AddParameter("email", PropertyDefinition.DefineString(
            "Filter by contact email."))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean(
            "Active/inactive hosts. Default: true."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "Filter by port (e.g., 443)."))
        .AddParameter("endpoint", PropertyDefinition.DefineString(
            "Filter by endpoint (e.g., 'dns')."))
        .AddParameter("page_size", PropertyDefinition.DefineNumber(
            "Results per page. Default: 4."))
        .AddParameter("page_number", PropertyDefinition.DefineNumber(
            "Pagination page. Default: 1."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Filter by agent location."))
        .Validate()
        .Build();
    }

    private FunctionDefinition BuildGetUserInfoFunction()
    {
        return new FunctionDefinitionBuilder(
            "get_user_info",
            "Get user account details (timezone, tokens, etc). Always include detail_response.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Full profile vs basic (email/timezone). Required."))
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
  string content = $@"
You are a network monitoring and security assistant named {llmType}. Your role is to:
1. **Execute tasks** using the provided tools when needed.
2. **Explain results** in clear, non-technical terms (avoid raw JSON/function output).
3. **Prioritize security**

### **Tool Usage Rules**
- **Parameter Efficiency**: 
  - ONLY include parameters with explicit values. Omit null/empty fields.

- **Error Handling**:
  - If a tool fails, explain the issue to the user **before** retrying or switching tools.
    - Example: *""The scan failed because the target IP is unreachable. Verify the address or try a different tool.""*

- **Tool Selection**:
  - **Ongoing Monitoring Tools** (run continuously):
    - `add_host` / `edit_host`: Configure hosts for long-term monitoring.
    - `get_host_data` / `get_host_list`: Review historical or current status.
  - **Immediate Execution Tools** (single results):
    - `run_nmap` / `run_openssl`: One-time scans/tests.
    - `test_quantum_safety`: Instant cryptographic checks.

### **Result Formatting Guide**
Always transform tool outputs into **user-friendly summaries**:
1. **For Monitoring Tools**:
   - ✅ *""Host `example.com` (HTTPS) is now monitored. Last check: 200ms response, SSL valid until 2025-10-01.""*
   - ❌ Avoid: `{{""status"":""up"",""response_time"":200}}`.

2. **For Scans/Tests**:
   - ✅ *""Nmap found 3 open ports on `192.168.1.1`: 22 (SSH), 80 (HTTP), 443 (HTTPS). No critical vulnerabilities detected.""*
   - ❌ Avoid raw Nmap JSON.

3. **For Errors**:
   - ✅ *""Couldn’t scan `example.com:8080`. The port may be blocked or the host offline.""

### **Proactive Guidance**
- Suggest next steps:  
  *""Would you like to set up alerts for this host?""*  
  *""I can run a vulnerability scan if needed.""*
- Flag security risks:  
  *""Warning: Port 22 (SSH) is open with default credentials. Recommend hardening.""";
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
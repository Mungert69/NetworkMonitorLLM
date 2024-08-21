using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
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
public class NmapToolsBuilder : IToolsBuilder
{
    private readonly FunctionDefinition fn_get_user_info;
    private readonly FunctionDefinition fn_run_nmap;
    public NmapToolsBuilder()
    {

        fn_get_user_info = new FunctionDefinitionBuilder("get_user_info", "Get information about the user")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all user details. Set to false if only basic info is required"))
        .Validate()
        .Build();


        fn_run_nmap = new FunctionDefinitionBuilder("run_nmap", "Run nmap command")
      .AddParameter("scan_options", PropertyDefinition.DefineString("Scan options, required"))
      .AddParameter("target", PropertyDefinition.DefineString("The target, required"))
      .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the scan, optional"))
      .Validate()
      .Build();

      _tools = new List<ToolDefinition>()
        {
            new ToolDefinition() { Function = fn_get_user_info, Type="function"  },
            new ToolDefinition() { Function = fn_run_nmap, Type="function"  }
        };

    }


    private readonly List<ToolDefinition> _tools;

    public List<ToolDefinition> Tools => _tools;

    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        string content = "You are a network scanning assistant specializing in network scanning using nmap. Your primary task is to translate user requests into the appropriate nmap command components, ensuring that the command is accurate, efficient, and safe. Key Responsibilities: 1. Understanding User Intent: Identify the user's primary goal (e.g., basic ping scan, detailed port scan, service/version detection, OS detection, or vulnerability assessment). Determine the type of target (single IP, IP range, domain name, or subnet) and the depth of the scan required. 2. Constructing the Command: Scan Options (scan_options): Combine the relevant nmap flags and options to match the user's intent. Example options include: Basic Scans: -sn for ping scan. Port Scanning: -sS for TCP SYN scan, -p <ports> to specify ports. Service/Version Detection: -sV. OS Detection: -O. Aggressive Scans: -A for a comprehensive scan. Stealth and Timing Options: -T<0-5>, -Pn for stealth scans. Additional Options: --script <script_name>, --traceroute, -v, etc. Target (target): Always include the target in the target parameter. This is the IP address, hostname, domain name, or subnet that you are scanning. Example targets include: A single IP address: 192.168.1.1 An IP range: 192.168.1.1-254 A domain name: example.com A subnet: 192.168.1.0/24 3. Running Vulnerability Scans with NSE Scripts: If the user requests a vulnerability scan, or if the scan involves checking for specific security vulnerabilities, you should utilize NSE scripts. Common options include: -sC to run the default set of NSE scripts. --script <script_name> to specify particular scripts for vulnerabilities or checks, such as vuln for a general vulnerability scan. Some scripts may require additional arguments, which should be included in the scan_options. Example: --script vuln. Ensure that the appropriate scripts are selected based on the user’s intent. 4. Execution: Ensure that the scan_options include all relevant scanning flags and that the target correctly specifies what needs to be scanned. Call the run_nmap function using the constructed scan_options and target parameters. Examples: User Request: \"Scan the IP address 1.1.1.1 and use the email@test.com-localhost agent location\" Function Call: {\"scan_options\": \"-sS\", \"target\": \"1.1.1.1\", \"agent_location\": \"email@test.com-localhost\"} User Request: \"Scan the IP host test.com with service/version detection.\" Function Call: {\"scan_options\": \"-sS -sV\", \"target\": \"test.com\"} User Request: \"Check 192.168.1.1 port 80 for vulnerabilities.\" Function Call: {\"scan_options\": \"-p 80 --script vuln\", \"target\": \"192.168.1.1\"}";

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

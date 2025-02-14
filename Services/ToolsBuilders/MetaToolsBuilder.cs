using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services
{
    public class MetaToolsBuilder : IToolsBuilder
    {
        private readonly FunctionDefinition fn_run_metasploit;
        private readonly FunctionDefinition fn_search_metasploit_modules;
           private readonly FunctionDefinition fn_get_metasploit_module_info;

        public MetaToolsBuilder()
        {
            // Define the run_metasploit function
            // Define the run_metasploit function
            fn_run_metasploit = new FunctionDefinitionBuilder("run_metasploit", "This function executes a Metasploit module based on the user's specifications. Use it to perform tasks such as exploiting a vulnerability, conducting scans, or gathering post-exploitation data.")
                .AddParameter("module_name", PropertyDefinition.DefineString("The name of the Metasploit module to run, required. Examples include 'exploit/windows/smb/ms17_010_eternalblue' for the EternalBlue vulnerability."))
                .AddParameter("module_options", PropertyDefinition.DefineObject(
                    new Dictionary<string, PropertyDefinition>(),
                    null,
                    false,
                    "The options for the module, optional. These should be key-value pairs to configure the module, such as 'RHOSTS' for the target IP address, 'PAYLOAD' for the payload to use, and 'LHOST' for the attacker's IP in reverse shell scenarios.",
                    null
                ))
                .AddParameter("target", PropertyDefinition.DefineString("The target, required. Specify the IP address, range, or domain you wish to target."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the module, optional. Use this if you need the module to be executed from a specific network segment or geographic location."))
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Increase this if you need more data returned by the search. Be careful with using larger numbers as a lot of data can be returned. Consider using a more targeted search term instead."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data."))
                .Validate()
                .Build();

            // Define the search_metasploit_modules function
            fn_search_metasploit_modules = new FunctionDefinitionBuilder("search_metasploit_modules", "Search for Metasploit modules using msfconsole's search command. Provide any combination of search filters to narrow down the results. This function constructs the msfconsole search command based on the provided parameters.")
                .AddParameter("module_type", PropertyDefinition.DefineString("Module type to search for. Options include 'exploit', 'auxiliary', 'post', 'payload', 'encoder', 'nop'. Corresponds to the 'type' search filter."))
                .AddParameter("platform", PropertyDefinition.DefineString("Platform to search for. Examples include 'windows', 'linux', 'multi', etc. Corresponds to the 'platform' search filter."))
                .AddParameter("architecture", PropertyDefinition.DefineString("Architecture to search for. Examples include 'x86', 'x64'. Corresponds to the 'arch' search filter."))
                .AddParameter("cve", PropertyDefinition.DefineString("CVE identifier to search for. Format: 'CVE-YYYY-NNNN'. Corresponds to the 'cve' search filter."))
                .AddParameter("edb", PropertyDefinition.DefineString("Exploit-DB ID to search for. Corresponds to the 'edb' search filter."))
                .AddParameter("rank", PropertyDefinition.DefineString("Minimum rank of modules to include. Options include 'excellent', 'great', 'good', 'normal', 'average', 'low', 'manual'. Corresponds to the 'rank' search filter."))
                .AddParameter("keywords", PropertyDefinition.DefineString("Additional keywords to search for in module names and descriptions."))
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Limit the number of lines returned in the search results. Use this to control output size, especially when the search yields many results. For example, setting this to 20 will return the first 20 matching modules."))
                .AddParameter("page", PropertyDefinition.DefineInteger("Specify the page number to paginate through large search results. Use in conjunction with number_lines to navigate sequentially through results, e.g., page 2 will show results after the first number_lines matches."))
                .Validate()
                .Build();

            // Define the get_metasploit_module_info function
            fn_get_metasploit_module_info = new FunctionDefinitionBuilder("get_metasploit_module_info", "Retrieve detailed information about a specific Metasploit module. Use this function to understand how to configure and use a module, including its options and supported targets.")
                .AddParameter("module_name", PropertyDefinition.DefineString("The full name of the Metasploit module to retrieve information for. Examples include 'exploit/windows/smb/ms17_010_eternalblue'."))
                .Validate()
                .Build();
         

            // Define the tools list
            _tools = new List<ToolDefinition>()
{
    new ToolDefinition() { Function = fn_run_metasploit, Type = "function" },
    new ToolDefinition() { Function = fn_search_metasploit_modules, Type = "function" },
    new ToolDefinition() { Function = fn_get_metasploit_module_info, Type = "function" },
};

        }

        private readonly List<ToolDefinition> _tools;

        public List<ToolDefinition> Tools => _tools;

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = @$"# Metasploit Security Assistant (v2.4)
**System Time:** {currentTime}

## Core Defaults (Hardcoded Safeguards)

### 1. Target Configuration
```auto-params
RHOSTS = 192.168.1.1-254  // Common private IP range
LHOST = 10.0.0.5          // Default callback IP
PAYLOAD = windows/meterpreter/reverse_https
TIMEOUT = 90              // Seconds
THREADS = 2               // Conservative parallelism

2. Module Selection Rules

    First Search Filter (REQUIRED):

        Minimum Rank: 'good'

        Platform: windows OR linux

        Year Range: 2018-{DateTime.Now.Year}

    Fallback Strategy:
    If no matches:

        Expand year range by 5 years

        Allow 'average' rank modules

        Add 'check' mode: true

3. Execution Safety
safety-profile
Copy

Exploit Attempts:
- Max 3 retries
- 15s delay between attempts
- Auto-rollback on service crash detection

Scanning:
- Rate limit: 50 packets/sec
- Never scan UDP/137-139 (AD protocols)
- Blocklist: 22, 3389, 5985 (critical services)

4. Error Recovery Defaults
failure-handling
Copy

Timeout:
  Retry with:
  - TIMEOUT += 30
  - VERBOSE = true

Access Denied:
  Switch to:
  - PAYLOAD = generic/shell_reverse_tcp
  - DisablePost = true

Session Drop:
  Auto-reconnect:
  - Max attempts: 2
  - SessionExpiration = 300

Example Workflow

User Request: ""Check EternalBlue vulnerability""

    search_metasploit_modules:

        keywords: eternalblue windows smb

        rank: excellent

        platform: windows

    get_metasploit_module_info:

        module_name: exploit/windows/smb/ms17_010_eternalblue

    run_metasploit:

        module_name: exploit/windows/smb/ms17_010_eternalblue

        module_options:
        RHOSTS: 192.168.1.100-200
        VERBOSE: true
        CHECK: true

        target: 192.168.1.150";

            var chatMessage = new ChatMessage()
            {
                Role = "system",
                Content = content
            };

            var chatMessages = new List<ChatMessage>
            {
                chatMessage
            };


            return chatMessages;
        }

    }
}

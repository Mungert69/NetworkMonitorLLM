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
        fn_add_host = MonitorTools.BuildAddHostFunction();
        fn_edit_host = MonitorTools.BuildEditHostFunction();
        fn_get_host_data = MonitorTools.BuildGetHostDataFunction();
        fn_get_host_list = MonitorTools.BuildGetHostListFunction();

        fn_are_functions_running = CommonTools.BuildAreFunctionsRunning();
        fn_cancel_functions = CommonTools.BuildCancelFunctions();
        fn_get_user_info = CommonTools.BuildGetUserInfoFunction();
        fn_get_agents = CommonTools.BuildGetAgentsFunction();

        fn_run_busybox = CommonTools.BuildRunBusyboxFunction();



        fn_run_nmap = SecurityTools.BuildNmapFunction();
        fn_run_openssl = SecurityTools.BuildOpenSslFunction();

        // Define the test_quantum_safety function
        fn_test_quantum_safety = QuantumTools.BuildTestQuantumSafetyFunction();
        // Define the scan_quantum_ports function
        fn_scan_quantum_ports = QuantumTools.BuildScanQuantumPortsFunction();

        // Build the tools list based on user account type
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
            new ToolDefinition() { Function = fn_run_nmap, Type = "function" },
            new ToolDefinition() { Function = fn_run_openssl, Type = "function" },
            new ToolDefinition() { Function = fn_test_quantum_safety, Type = "function" },
            new ToolDefinition() { Function = fn_scan_quantum_ports, Type = "function" },
            new ToolDefinition() { Function = fn_run_busybox, Type = "function" }
        };
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
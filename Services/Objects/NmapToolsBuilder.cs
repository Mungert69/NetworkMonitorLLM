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

namespace NetworkMonitor.LLM.Services
{
    public class NmapToolsBuilder : IToolsBuilder
    {
        private readonly FunctionDefinition fn_get_user_info;
        private readonly FunctionDefinition fn_run_nmap;
        private readonly FunctionDefinition fn_run_openssl;

        public NmapToolsBuilder()
        {
            fn_get_user_info = new FunctionDefinitionBuilder("get_user_info", "Get information about the user")
                .AddParameter("detail_response", PropertyDefinition.DefineBoolean("If true, retrieve all available user details. If false, provide only basic user information."))
                .Validate()
                .Build();

            fn_run_nmap = new FunctionDefinitionBuilder("run_nmap", "This function calls nmap. Create the parameters based upon the user's request. The response from the function will contain a result with the output of running nmap on the remote agent. Give the user a summary of the output that answers their query.")
                .AddParameter("scan_options", PropertyDefinition.DefineString("The nmap scan options. Must reflect the user's desired scan goal, e.g., ping scan, vulnerability scan, etc."))
                .AddParameter("target", PropertyDefinition.DefineString("Target to scan, like an IP, domain, or subnet."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("Optional. If available, specify which agent will run the scan."))
                .Validate()
                .Build();

            fn_run_openssl = new FunctionDefinitionBuilder("run_openssl", "This function calls openssl. Construct the command options based on the user's request for security checks on SSL/TLS configurations. Provide a summary of the findings and recommendations based on the analysis.")
                .AddParameter("command_options", PropertyDefinition.DefineString("Construct the relevant openssl command options based on the user’s request, e.g., certificate analysis, protocol vulnerabilities."))
                .AddParameter("target", PropertyDefinition.DefineString("The server or service you are scanning for security issues."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("Optional. Location of the agent that will execute the openssl command."))
                .Validate()
                .Build();

            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_get_user_info, Type = "function" },
                new ToolDefinition() { Function = fn_run_nmap, Type = "function" },
                new ToolDefinition() { Function = fn_run_openssl, Type = "function" }
            };
        }

        private readonly List<ToolDefinition> _tools;

        public List<ToolDefinition> Tools => _tools;

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
        {
            string content = "You are a virtual security consultant specializing in network and server security assessments. Your primary responsibility is to help users by simulating security audits using tools like **Nmap** and **OpenSSL**, providing insights into potential vulnerabilities, and offering remediation advice based on your findings.\n\n" +
                "### Key Responsibilities:\n" +
                "1. **Understanding User Intent**:\n" +
                "- Your task is to interpret user requests accurately, understanding their specific security goals, such as conducting vulnerability scans, checking SSL/TLS configurations, or assessing network security.\n" +
                "- Determine whether the user requires a **basic scan**, **in-depth analysis**, or a **targeted security audit** on a particular service or network.\n" +
                "2. **Constructing and Executing Commands**:\n" +
                "- Based on user input, you will translate requests into the appropriate Nmap or OpenSSL commands. These commands will emulate real-world security tools used by professional auditors to detect weaknesses in network infrastructure or service configurations.\n" +
                "- **Nmap Tasks**: Focus on detecting open ports, identifying service versions (-sV), performing OS detection (-O), and running vulnerability scripts (--script vuln). Ensure to include necessary scan options such as stealth options (-Pn) or timing controls (-T0-5).\n" +
                "  - Example: A user requests to scan a domain for service/version detection. Your function call would look like: {\"scan_options\": \"-sV\", \"target\": \"example.com\"}.\n" +
                "- **OpenSSL Tasks**: Analyze SSL/TLS certificates, check encryption methods, and identify outdated or weak encryption protocols. Use OpenSSL to perform detailed security checks on specific services.\n" +
                "  - Example: If a user asks to check the SSL certificate of a server, use a command like: {\"command_options\": \"s_client -connect example.com:443\", \"target\": \"example.com\"}.\n" +
                "3. **Security Auditing Process**:\n" +
                "- Similar to a professional audit, after running a scan or analysis, you will provide the user with a clear and detailed report. This report should outline the findings and highlight any vulnerabilities or risks identified during the scan.\n" +
                "- Offer recommendations for remediation based on security best practices, such as updating weak encryption algorithms, closing unnecessary open ports, or patching unpatched software.\n" +
                "4. **Adhering to Security Standards**:\n" +
                "- Be mindful of regulatory standards, such as **GDPR**, **HIPAA**, or **PCI DSS**, especially when scanning systems that may hold sensitive data. Provide guidance on compliance where relevant, ensuring users understand potential risks or non-compliance issues.\n" +
                "5. **Effective Use of Tools**:\n" +
                "- Ensure that the tools (Nmap, OpenSSL) are used efficiently, balancing thoroughness with performance to minimize resource usage and network disruption, especially on large networks.\n\n" +
                "### Example User Requests and Responses:\n" +
                "- **User Request**: \"Run a vulnerability scan on 192.168.1.1 for port 80.\"\n" +
                "  - **Response**: Use the Nmap command: {\"scan_options\": \"-p 80 --script vuln\", \"target\": \"192.168.1.1\"}.\n" +
                "- **User Request**: \"Check the SSL configuration of test.com.\"\n" +
                "  - **Response**: Use OpenSSL to check the SSL certificate with the command: {\"command_options\": \"s_client -connect test.com:443\", \"target\": \"test.com\"}.\n" +
                "Your overall goal is to simulate a thorough, professional security audit and provide users with actionable insights for improving their security posture.";

            if (serviceObj.IsUserLoggedIn)
                content += $" The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}.";
            else
                content += $" The user is not logged in, the time is {currentTime}, ask the user for an email to add hosts etc.";

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

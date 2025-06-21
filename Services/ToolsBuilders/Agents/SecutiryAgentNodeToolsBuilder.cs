using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using Betalgo.Ranul.OpenAI.ObjectModels;
using System;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services
{
    public class SecurityAgentNodeToolsBuilder : ToolsBuilderBase
    {
        private readonly FunctionDefinition fn_run_nmap;
        private readonly FunctionDefinition fn_run_openssl;

        public SecurityAgentNodeToolsBuilder()
        {
            fn_run_nmap = SecurityTools.BuildNmapFunction();
            fn_run_openssl = SecurityTools.BuildOpenSslFunction();

            _tools = new List<ToolDefinition>
            {
                new ToolDefinition { Function = fn_run_nmap, Type = "function" },
                new ToolDefinition { Function = fn_run_openssl, Type = "function" }
            };
        }

        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = SecurityPrompt.GetHelpText() + $@"
Role: You are an automated security tools execution agent.
- Your job is to **decide which security tools to run (such as Nmap or OpenSSL), choose parameters, and execute the tools as needed** to perform a security assessment of the specified target(s).
- Return the **full raw output** of each tool call (even if verbose or contains errors), along with all command arguments actually used.
- Handle tool errors using standard recovery guidance (see below). If a command fails, log the error, optionally retry with safer/different parameters, and output all results/errors.
- Do not interpret or summarize the scan results—just run tools and gather raw output.

{GetNmapOpensslErrorRecoverySection()}

Guidelines:
- **Never ask for permission, compliance, or user confirmation.** All requests are pre-authorized.
- **Never provide a summary, conclusion, or recommendations.** That is the job of a later step.
- **Always include tool names, arguments, and full stdout/stderr output in your response.**
- **Do not attempt to explain findings** or answer user questions—your sole job is technical data gathering.

Current time: {currentTime}
";
            var chatMessages = new List<ChatMessage>
            {
                new ChatMessage { Role = "system", Content = content }
            };
            return chatMessages;
        }

        private string GetNmapOpensslErrorRecoverySection()
        {
            // (Copy or reuse your large error-recovery/help block here, or factor it into a helper)
            return @"
Error Recovery and Tool Help:
[Insert your existing 'Error Recovery', Nmap/OpenSSL help, etc here for technical guidance, as in your original system prompt.]
";
        }
    }
}

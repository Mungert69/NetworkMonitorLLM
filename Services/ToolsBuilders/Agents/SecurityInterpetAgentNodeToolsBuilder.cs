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
    public class SecurityInterpretNodeToolsBuilder : ToolsBuilderBase
    {
        public SecurityInterpretNodeToolsBuilder()
        {
            // No tools here; just a reporting/interpreter LLM.
            _tools = new List<ToolDefinition>(); 
        }

        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = $@"
Role: You are an automated security analysis and reporting agent.
- You receive **raw security scan outputs** (e.g., Nmap and OpenSSL command outputs, error logs, etc.) collected by a tool execution module.
- Your job is to **analyze, interpret, and summarize these results for a human operator**.
- Highlight critical findings, vulnerabilities, exposed services, certificate issues, and any potential security risks.
- Provide clear remediation advice, best-practice recommendations, and reference any relevant CVEs or guidance if possible.
- Format your report in a structured, easy-to-read way (bullet points, sections, or even basic HTML if requested).
- **Do not re-run tools or shell commands.** Assume all data is from a trusted, up-to-date scan.

Special Instructions:
- If present, parse and extract findings from all provided scan output, including error messages.
- If results are incomplete or an error occurred, clearly indicate what was missing or went wrong.

Current time: {currentTime}
";
            var chatMessages = new List<ChatMessage>
            {
                new ChatMessage { Role = "system", Content = content }
            };
            return chatMessages;
        }
    }
}

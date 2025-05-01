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
    public class QuantumExpertToolsBuilder : ToolsBuilderBase
    {
        private readonly FunctionDefinition fn_test_quantum_safety;
        private readonly FunctionDefinition fn_scan_quantum_ports;
        private readonly FunctionDefinition fn_get_quantum_algorithm_info;
        private readonly FunctionDefinition fn_validate_quantum_config;

        public QuantumExpertToolsBuilder()
        {
            fn_test_quantum_safety = QuantumTools.BuildTestQuantumSafetyFunction();
            fn_scan_quantum_ports = QuantumTools.BuildScanQuantumPortsFunction();
            fn_get_quantum_algorithm_info = QuantumTools.BuildQuantumAlgoInfoFunction();

            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_test_quantum_safety, Type = "function" },
                new ToolDefinition() { Function = fn_scan_quantum_ports, Type = "function" },
                new ToolDefinition() { Function = fn_get_quantum_algorithm_info, Type = "function" },
               // new ToolDefinition() { Function = fn_validate_quantum_config, Type = "function" },
            };
        }

        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = @$"System Time: {currentTime}
 Role Clarification:
- You are an automated Quantum Security expert module integrated within the Network Monitor Assistant.
- The Network Monitor Assistant has already obtained user consent and verified compliance before invoking your scanning functions.
- DO NOT ask for permission or compliance checks—assume all requests are pre-authorized.
- Your sole responsibility is to call tools to execute requested quantum checks and provide technical analysis.
"
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
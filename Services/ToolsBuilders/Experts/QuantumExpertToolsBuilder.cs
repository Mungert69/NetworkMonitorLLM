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
            string content = @$"# Quantum Security Expert (v1.0)
**System Time:** {currentTime}

## Core Defaults (Hardcoded Safeguards)

### 1. Target Configuration
```auto-params
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 59000
DEFAULT_ALGORITHMS = kyber512, dilithium2, falcon512
NMAP_OPTIONS = -T4 --open

2. Algorithm Selection Rules
rules


- Minimum Security Level: NIST PQC Round 3 Finalists
- Fallback Strategy:
  If no supported algorithms are found:
    - Test for hybrid (classical + quantum) configurations
    - Check for deprecated algorithms (e.g., RSA, ECC)

3. Execution Safety
safety-profile


- Max 3 retries per algorithm
- 5s delay between tests
- Blocklist: Ports 22 (SSH), 3389 (RDP), 5985 (WinRM)

4. Error Recovery Defaults
failure-handling


- Timeout:
  Retry with:
  - TIMEOUT += 10000
  - VERBOSE = true
- Connection Drop:
  Auto-reconnect:
  - Max attempts: 2
  - SessionExpiration = 300

Example Workflow
User Request: ""Check quantum safety of example.com""

    scan_quantum_ports:

        target: example.com

        ports: [443, 8443]

        algorithms: [kyber512, dilithium2]

        timeout: 60000

    test_quantum_safety:

        target: example.com

        port: 443

        algorithms: [kyber512, dilithium2]

        timeout: 30000

    get_quantum_algorithm_info:


        algorithm: mlkem";


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
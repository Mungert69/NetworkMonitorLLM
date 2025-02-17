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
    public class QuantumToolsBuilder : ToolsBuilderBase
    {
        private readonly FunctionDefinition fn_test_quantum_safety;
        private readonly FunctionDefinition fn_scan_quantum_ports;
        private readonly FunctionDefinition fn_get_quantum_algorithm_info;
        private readonly FunctionDefinition fn_validate_quantum_config;

        public QuantumToolsBuilder()
        {
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

            // Define the get_quantum_algorithm_info function
            fn_get_quantum_algorithm_info = new FunctionDefinitionBuilder("get_quantum_algorithm_info", "Retrieves detailed information about a specific quantum-safe algorithm. Use this to understand the properties, strengths, and weaknesses of a given algorithm.")
                .AddParameter("algorithm_name", PropertyDefinition.DefineString("The name of the quantum-safe algorithm to retrieve information for, required. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'."))
                .Validate()
                .Build();

            // Define the validate_quantum_config function
            fn_validate_quantum_config = new FunctionDefinitionBuilder("validate_quantum_config", "Validates a quantum-safe configuration for a target server. Use this to ensure that the server's configuration meets quantum-safe standards.")
                .AddParameter("target", PropertyDefinition.DefineString("The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."))
                .AddParameter("port", PropertyDefinition.DefineInteger("The TLS port to validate, optional. Default is 443."))
                .AddParameter("algorithms", PropertyDefinition.DefineArray(PropertyDefinition.DefineString("The list of quantum-safe algorithms to validate, optional. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'. If not provided, all enabled algorithms will be validated.")))
                .Validate()
                .Build();

            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_test_quantum_safety, Type = "function" },
                new ToolDefinition() { Function = fn_scan_quantum_ports, Type = "function" },
                new ToolDefinition() { Function = fn_get_quantum_algorithm_info, Type = "function" },
                new ToolDefinition() { Function = fn_validate_quantum_config, Type = "function" },
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
DEFAULT_ALGORITHMS = Kyber512, Dilithium2, Falcon512
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

        algorithms: [Kyber512, Dilithium2]

        timeout: 60000

    test_quantum_safety:

        target: example.com

        port: 443

        algorithms: [Kyber512, Dilithium2]

        timeout: 30000

    validate_quantum_config:

        target: example.com

        port: 443

        algorithms: [Kyber512, Dilithium2]";
            

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
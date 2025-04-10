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

public class QuantumTools
{
    public static FunctionDefinition BuildTestQuantumSafetyFunction()
    {
        return new FunctionDefinitionBuilder("test_quantum_safety", "Tests a target endpoint for quantum-safe cryptographic support using specified algorithms. Use this to verify if a server supports post-quantum cryptography (PQC) algorithms.")
            .AddParameter("target", PropertyDefinition.DefineString("The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."))
            .AddParameter("port", PropertyDefinition.DefineInteger("The TLS port to test, optional. Default is 443."))
            .AddParameter("algorithms", PropertyDefinition.DefineArray(PropertyDefinition.DefineString("The list of quantum-safe algorithms to test, optional. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'. If not provided, all enabled algorithms will be tested.")))
            .AddParameter("timeout", PropertyDefinition.DefineInteger("The maximum time (in milliseconds) to wait for the test to complete, optional. Default is 59000ms."))
            .Validate()
            .Build();
    }

    // Define the scan_quantum_ports function
    public static FunctionDefinition BuildScanQuantumPortsFunction()
    {
        return new FunctionDefinitionBuilder("scan_quantum_ports", "Scans a target for open ports and tests each port for quantum-safe cryptographic support. Use this to identify vulnerable ports that lack quantum-safe encryption.")
            .AddParameter("target", PropertyDefinition.DefineString("The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."))
            .AddParameter("ports", PropertyDefinition.DefineArray(PropertyDefinition.DefineInteger("The list of ports to scan, optional. If not provided, Nmap will be used to discover open ports.")))
            .AddParameter("algorithms", PropertyDefinition.DefineArray(PropertyDefinition.DefineString("The list of quantum-safe algorithms to test, optional. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'. If not provided, all enabled algorithms will be tested.")))
            .AddParameter("timeout", PropertyDefinition.DefineInteger("The maximum time (in milliseconds) to wait for the scan to complete, optional. Default is 59000ms."))
            .AddParameter("nmap_options", PropertyDefinition.DefineString("Custom Nmap options for port scanning, optional. Default is '-T4 --open'."))
            .Validate()
            .Build();
    }


    public static FunctionDefinition BuildQuantumAlgoInfoFunction()
    {
        return new FunctionDefinitionBuilder("get_quantum_algorithm_info", "Retrieves detailed information about a specific quantum-safe algorithm. Use this to understand the properties, strengths, and weaknesses of a given algorithm.")
                .AddParameter("algorithm_name", PropertyDefinition.DefineString("The name of the quantum-safe algorithm to retrieve information for, required. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'."))
                .Validate()
                .Build();
    }

    // Define the validate_quantum_config function
    /*
    fn_validate_quantum_config = new FunctionDefinitionBuilder("validate_quantum_config", "Validates a quantum-safe configuration for a target server. Use this to ensure that the server's configuration meets quantum-safe standards.")
        .AddParameter("target", PropertyDefinition.DefineString("The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."))
        .AddParameter("port", PropertyDefinition.DefineInteger("The TLS port to validate, optional. Default is 443."))
        .AddParameter("algorithms", PropertyDefinition.DefineArray(PropertyDefinition.DefineString("The list of quantum-safe algorithms to validate, optional. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'. If not provided, all enabled algorithms will be validated.")))
        .Validate()
        .Build();*/



}
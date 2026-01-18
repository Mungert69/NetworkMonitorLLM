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
        return new FunctionDefinition
        {
            Name = "test_quantum_safety",
            Description = "Tests a target endpoint for quantum-safe cryptographic support using specified algorithms. Use this to verify if a server supports post-quantum cryptography (PQC) algorithms.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["target"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."
                    },
                    ["port"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The TLS port to test, optional. Default is 443."
                    },
                    ["algorithms"] = new PropertyDefinition
                    {
                        Type = "array",
                        Items = new PropertyDefinition
                        {
                            Type = "string",
                            Description = "The list of quantum-safe algorithms to test, optional. If not provided, all enabled algorithms will be tested."
                        }
                    },
                    ["timeout"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The maximum time (in milliseconds) to wait for the test to complete, optional. Default is 59000ms."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Preferred agent location if testing from different network perspectives. " +
                                      "Important for testing internal vs external services or geographic-specific configurations."
                    }
                },
                Required = new List<string> { "target" }
            }
        };
    }

    public static FunctionDefinition BuildScanQuantumPortsFunction()
    {
        return new FunctionDefinition
        {
            Name = "scan_quantum_ports",
            Description = "Scans a target for open ports and tests each port for quantum-safe cryptographic support. Use this to identify vulnerable ports that lack quantum-safe encryption.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["target"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."
                    },
                    ["ports"] = new PropertyDefinition
                    {
                        Type = "array",
                        Items = new PropertyDefinition
                        {
                            Type = "integer",
                            Description = "The list of ports to scan, optional. If not provided, Nmap will be used to discover open ports."
                        }
                    },
                    ["algorithms"] = new PropertyDefinition
                    {
                        Type = "array",
                        Items = new PropertyDefinition
                        {
                            Type = "string",
                            Description = "The list of quantum-safe algorithms to test, optional. If not provided, all enabled algorithms will be tested."
                        }
                    },
                    ["timeout"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The maximum time (in milliseconds) to wait for the scan to complete, optional. Default is 59000ms."
                    },
                    ["nmap_options"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Custom Nmap options for port scanning, optional. Default is '-T4 --open'."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Preferred agent location if testing from different network perspectives. " +
                                      "Important for testing internal vs external services or geographic-specific configurations."
                    }
                },
                Required = new List<string> { "target" }
            }
        };
    }

    public static FunctionDefinition BuildQuantumAlgoInfoFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_quantum_algorithm_info",
            Description = "Retrieves detailed information about a specific quantum-safe algorithm. Use this to understand the properties, strengths, and weaknesses of a given algorithm.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["algorithm_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the quantum-safe algorithm to retrieve information for, required. Examples include 'Kyber512', 'Dilithium2', 'Falcon512'."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Preferred agent location if testing from different network perspectives. " +
                                      "Important for testing internal vs external services or geographic-specific configurations."
                    }
                },
                Required = new List<string> { "algorithm_name" }
            }
        };
    }

    public static FunctionDefinition BuildTestQuantumCertificateFunction()
    {
        return new FunctionDefinition
        {
            Name = "test_quantum_certificate",
            Description = "Checks a target endpoint for quantum-safe certificate usage during the TLS handshake. Use this to assess whether the certificate uses post-quantum or hybrid signature/public-key algorithms.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["target"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The target server IP or hostname, required. Example: 'example.com' or '192.168.1.1'."
                    },
                    ["port"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The TLS port to test, optional. Default is 443."
                    },
                    ["timeout"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The maximum time (in milliseconds) to wait for the check to complete, optional. Default is 59000ms."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Preferred agent location if testing from different network perspectives. " +
                                      "Important for testing internal vs external services or geographic-specific configurations."
                    }
                },
                Required = new List<string> { "target" }
            }
        };
    }
}

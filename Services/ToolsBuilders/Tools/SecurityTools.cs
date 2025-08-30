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

public class SecurityTools
{
    public static FunctionDefinition BuildNmapFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_nmap",
            Description = "Executes an nmap network scan based on the user's request. " +
                          "The function should be called when the user needs network discovery, port scanning, service detection, " +
                          "vulnerability assessment, or other network reconnaissance tasks. " +
                          "Construct appropriate scan options based on the user's specific needs (e.g., stealth scanning, " +
                          "service version detection, OS fingerprinting). " +
                          "After receiving results, analyze the output to provide the user with: " +
                          "1) A concise summary of key findings, 2) Security implications, 3) Any recommended next steps. " +
                          "Highlight critical vulnerabilities or unusual findings prominently.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["scan_options"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Nmap command-line options to execute. " +
                                      "Should be constructed based on the user's specific request. " +
                                      "Examples: '-sV' for service version detection, '-O' for OS fingerprinting, " +
                                      "'-A' for aggressive scan, '-p-' for all ports, '--script vuln' for vulnerability scanning. " +
                                      "Combine options as needed (e.g., '-sS -p 80,443 -T4'). " +
                                      "Ensure options are valid and security-conscious (avoid overly aggressive scans without justification)."
                    },
                    ["target"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The target to scan - can be an IP address (e.g., '192.168.1.1'), " +
                                      "IP range ('192.168.1.0/24'), domain name ('example.com'), " +
                                      "or hostname. Validate the target with the user if ambiguous."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Preferred agent location if scanning from multiple possible locations. " +
                                      "Important for scanning internal vs external networks. " +
                                      "Example: 'us-east-1' for AWS region or 'corporate-dmz' for specific network segment."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Limit for output lines to return. Default to 50 for initial scans. " +
                                      "Increase for detailed analysis (e.g., 200-500 for full port scans), " +
                                      "but be mindful of response size. Consider filtering results first."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Pagination control for large result sets. Start with 1. " +
                                      "Increment to view additional portions of extensive scan results."
                    }
                },
                Required = new List<string> { "scan_options", "target" }
            }
        };
    }

    public static FunctionDefinition BuildOpenSslFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_openssl",
            Description = "Executes OpenSSL commands for security analysis of SSL/TLS configurations, certificates, " +
                          "and cryptographic protocols. Use when the user requests: certificate inspection, " +
                          "protocol support checks, cipher suite evaluation, or cryptographic vulnerability testing. " +
                          "Analyze results to provide: 1) Security grade of configuration, 2) Specific vulnerabilities found, " +
                          "3) Recommended fixes, 4) Compliance status with current best practices.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["command_options"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "OpenSSL command and options constructed for the specific task. " +
                                      "Examples: 's_client -connect example.com:443 -showcerts' for certificate analysis, " +
                                      "'ciphers -v' to list supported ciphers, 'x509 -text -noout' for certificate details. " +
                                      "Include all necessary flags for the requested analysis."
                    },
                    ["target"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Target server in format 'host:port' (e.g., 'example.com:443'), " +
                                      "or certificate file if analyzing local files. For SMTP/other protocols, " +
                                      "use format 'smtp.example.com:25' with appropriate protocol options."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Preferred agent location if testing from different network perspectives. " +
                                      "Important for testing internal vs external services or geographic-specific configurations."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Limit for output lines to return. Default to 100 for certificate analysis. " +
                                      "May need higher values (300+) for verbose outputs like full certificate chains."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Pagination control for extensive outputs (e.g., multi-certificate chains). " +
                                      "Start with 1, increment to view additional sections."
                    }
                },
                Required = new List<string> { "command_options", "target" }
            }
        };
    }

    public static FunctionDefinition BuildSecurityBooksQueryFunction()
    {
        const string description = @"
Search a **local** RAG/OpenSearch index for information from various sources. 
This tool never uses the public internet.

It executes a semantic (vector) or keyword search against a specified index that represents the data source. 
The OpenSearch backend uses the 'vector_search_mode' parameter to determine which embedding field to search.

The 'query_text' will be embedded and compared against the selected embedding field (e.g., 'content', 'question', or 'summary') in the index.

Use this function to retrieve relevant documents, answers, or summaries from the knowledge base.

This **specialized version** is for security workflows. It is intended to support other security tools such as 'run_nmap' and 'run_openssl' by providing:
  - Hardening guidance, remediation steps, and best practices extracted from security literature.
  - Contextual explanations of findings (e.g., vulnerable cipher suites, misconfigured services, weak SSL/TLS settings).
  - References and summaries from security books to justify or prioritize remediation actions.

You must specify:
  - 'query_text': The natural-language query or keywords. This will be embedded and used for the vector search against the selected embedding field.
  - 'index_name': Must be 'securitybooks'. This determines which knowledge base is queried.
Optionally:
  - 'vector_search_mode': Which embedding field to use for the vector search. Valid values: 'content', 'question', 'summary'. Defaults to 'content'.

Examples:
  - After parsing Nmap results (e.g., open port with outdated service), query: 
    'Recommended hardening steps for Apache HTTP server version 2.4' 
    (index_name='securitybooks', vector_search_mode='content').
  - After OpenSSL analysis reveals weak cipher suites, query: 
    'Best practices for disabling vulnerable TLS cipher suites and enabling modern alternatives' 
    (index_name='securitybooks', vector_search_mode='summary').
  - For general remediation guidance: 
    'Mitigation strategies for SSLv3 and TLS 1.0 deprecation' 
    (index_name='securitybooks', vector_search_mode='question' or 'summary').

Use this function whenever you need information from the local security knowledge base to interpret or act upon results from the other security tools.
";

        return new FunctionDefinition
        {
            Name = "execute_query_security",
            Description = description,
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The search query or question. This will be embedded and used for the vector search against the selected embedding field."
                    },
                    ["index_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Must be 'securitybooks'. This index contains curated security books and references to support analysis and remediation of findings from tools like Nmap and OpenSSL."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Determines which embedding field to use for the vector search: 'content', 'question', or 'summary'. Defaults to 'content'."
                    }
                },
                Required = new List<string> { "query_text", "index_name","vector_search_mode" }
            }
        };
    }
}

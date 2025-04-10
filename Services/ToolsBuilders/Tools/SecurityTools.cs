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
        return new FunctionDefinitionBuilder(
                "run_nmap",
                "Executes an nmap network scan based on the user's request. " +
                "The function should be called when the user needs network discovery, port scanning, service detection, " +
                "vulnerability assessment, or other network reconnaissance tasks. " +
                "Construct appropriate scan options based on the user's specific needs (e.g., stealth scanning, " +
                "service version detection, OS fingerprinting). " +
                "After receiving results, analyze the output to provide the user with: " +
                "1) A concise summary of key findings, 2) Security implications, 3) Any recommended next steps. " +
                "Highlight critical vulnerabilities or unusual findings prominently.")
                .AddParameter(
                    "scan_options",
                    PropertyDefinition.DefineString(
                        "Nmap command-line options to execute. " +
                        "Should be constructed based on the user's specific request. " +
                        "Examples: '-sV' for service version detection, '-O' for OS fingerprinting, " +
                        "'-A' for aggressive scan, '-p-' for all ports, '--script vuln' for vulnerability scanning. " +
                        "Combine options as needed (e.g., '-sS -p 80,443 -T4'). " +
                        "Ensure options are valid and security-conscious (avoid overly aggressive scans without justification)."))
                .AddParameter(
                    "target",
                    PropertyDefinition.DefineString(
                        "The target to scan - can be an IP address (e.g., '192.168.1.1'), " +
                        "IP range ('192.168.1.0/24'), domain name ('example.com'), " +
                        "or hostname. Validate the target with the user if ambiguous."))
                .AddParameter(
                    "agent_location",
                    PropertyDefinition.DefineString(
                        "Optional. Preferred agent location if scanning from multiple possible locations. " +
                        "Important for scanning internal vs external networks. " +
                        "Example: 'us-east-1' for AWS region or 'corporate-dmz' for specific network segment."))
                .AddParameter(
                    "number_lines",
                    PropertyDefinition.DefineInteger(
                        "Limit for output lines to return. Default to 50 for initial scans. " +
                        "Increase for detailed analysis (e.g., 200-500 for full port scans), " +
                        "but be mindful of response size. Consider filtering results first."))
                .AddParameter(
                    "page",
                    PropertyDefinition.DefineInteger(
                        "Pagination control for large result sets. Start with 1. " +
                        "Increment to view additional portions of extensive scan results."))
                .Validate()
                .Build();
    }

    public static FunctionDefinition BuildOpenSslFunction()
    {
        return new FunctionDefinitionBuilder(
                "run_openssl",
                "Executes OpenSSL commands for security analysis of SSL/TLS configurations, certificates, " +
                "and cryptographic protocols. Use when the user requests: certificate inspection, " +
                "protocol support checks, cipher suite evaluation, or cryptographic vulnerability testing. " +
                "Analyze results to provide: 1) Security grade of configuration, 2) Specific vulnerabilities found, " +
                "3) Recommended fixes, 4) Compliance status with current best practices.")
                .AddParameter(
                    "command_options",
                    PropertyDefinition.DefineString(
                        "OpenSSL command and options constructed for the specific task. " +
                        "Examples: 's_client -connect example.com:443 -showcerts' for certificate analysis, " +
                        "'ciphers -v' to list supported ciphers, 'x509 -text -noout' for certificate details. " +
                        "Include all necessary flags for the requested analysis."))
                .AddParameter(
                    "target",
                    PropertyDefinition.DefineString(
                        "Target server in format 'host:port' (e.g., 'example.com:443'), " +
                        "or certificate file if analyzing local files. For SMTP/other protocols, " +
                        "use format 'smtp.example.com:25' with appropriate protocol options."))
                .AddParameter(
                    "agent_location",
                    PropertyDefinition.DefineString(
                        "Optional. Preferred agent location if testing from different network perspectives. " +
                        "Important for testing internal vs external services or geographic-specific configurations."))
                .AddParameter(
                    "number_lines",
                    PropertyDefinition.DefineInteger(
                        "Limit for output lines to return. Default to 100 for certificate analysis. " +
                        "May need higher values (300+) for verbose outputs like full certificate chains."))
                .AddParameter(
                    "page",
                    PropertyDefinition.DefineInteger(
                        "Pagination control for extensive outputs (e.g., multi-certificate chains). " +
                        "Start with 1, increment to view additional sections."))
                .Validate()
                .Build();
    }


}
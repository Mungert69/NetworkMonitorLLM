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

public class PenetrationTools
{

    public static FunctionDefinition BuildRunMetasploitFunction()
    {
        return new FunctionDefinitionBuilder("run_metasploit",
            "Executes a Metasploit module with parameter validation. Structure requests as: " +
            "1. First search modules with search_metasploit_modules " +
            "2. Get module details with get_metasploit_module_info " +
            "3. Execute with required parameters. " +
            "Example: To exploit EternalBlue: {'module_name':'exploit/windows/smb/ms17_010_eternalblue','target':'192.168.1.5','module_options':{'RHOSTS':'192.168.1.5','LHOST':'10.0.0.1'}}")
        .AddParameter("module_name", PropertyDefinition.DefineString(
            "[REQUIRED] Full module path from search results. Example: 'exploit/windows/smb/ms17_010_eternalblue'"))
        .AddParameter("module_options", PropertyDefinition.DefineString(
            "JSON object with Metasploit module options. Must include 'RHOSTS'. " +
            "Example: { \"RHOSTS\": \"192.168.1.5\", \"LHOST\": \"10.0.0.1\", \"PAYLOAD\": \"windows/meterpreter/reverse_tcp\" }"))
        .AddParameter("target", PropertyDefinition.DefineString(
            "[REQUIRED] IP/Domain/CIDR range. Validate format first. Example: '192.168.1.0/24'"))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Predefined agent locations. Default: auto-assign based on target geoIP"))
        .AddParameter("number_lines", PropertyDefinition.DefineInteger(
            "Output lines to return. Default: 20. Max: 100."))
        .AddParameter("page", PropertyDefinition.DefineInteger(
            "Pagination for large outputs. Start with 1. Increment if 'truncated' flag is set."))
        .Validate()
        .Build();
    }
    public static FunctionDefinition BuildSearchMetasploitFunction()
    {
        return new FunctionDefinitionBuilder("search_metasploit_modules",
            "Search modules with filters. Always start penetration tests with this to find appropriate modules. " +
            "Example: Find Windows SMB exploits: {'module_type':'exploit','platform':'windows','service':'smb'}")
            .AddParameter("module_type", PropertyDefinition.DefineEnum(
                new List<string> { "exploit", "auxiliary", "post" },
                "Category filter. Multiple allowed with commas. Example: 'exploit,auxiliary'"))
            .AddParameter("platform", PropertyDefinition.DefineString(
                "OS filter. Use 'multi' for cross-platform"))
            .AddParameter("service", PropertyDefinition.DefineString(
                "Affected service filter"))
            .AddParameter("cve", PropertyDefinition.DefineString(
                "CVE ID with validation. Format: CVE-YYYY-NNNNN. Example: CVE-2017-0144"))
            .AddParameter("edb", PropertyDefinition.DefineString(
                "Exploit-DB ID. Must be numeric. Example: 42315"))
            .AddParameter("rank", PropertyDefinition.DefineEnum(
                new List<string> { "excellent", "great", "good", "average" },
                "Minimum reliability rating. Default: 'good'"))
            .AddParameter("keywords", PropertyDefinition.DefineString(
                "Space-separated search terms. Example: 'exchange privilege escalation'"))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger(
                "Results per page. Default: 10. Max: 50."))
            .AddParameter("page", PropertyDefinition.DefineInteger(
                "Pagination control. Start with 1. Increment if 'more_results'=true"))
                .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Predefined agent locations. Default: auto-assign based on target geoIP"))
            .Validate()
            .Build();
    }

    public static FunctionDefinition BuildMetasploitModuleInfoFunction()
    {
        return new FunctionDefinitionBuilder("get_metasploit_module_info",
            "Get module requirements BEFORE execution. Required step between search and run. " +
            "Example: {'module_name':'exploit/windows/smb/ms17_010_eternalblue'}")
            .AddParameter("module_name", PropertyDefinition.DefineString(
                "[REQUIRED] Exact module path from search results. Case-sensitive."))
            .AddParameter("show_options", PropertyDefinition.DefineBoolean(
                "Include full parameter details. Default: true"))
            .AddParameter("show_examples", PropertyDefinition.DefineBoolean(
                "Include usage examples. Default: true"))
                .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Predefined agent locations. Default: auto-assign based on target geoIP"))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger(
            "Output lines to return. Default: 20. Max: 100."))
            .AddParameter("page", PropertyDefinition.DefineInteger(
            "Pagination for large outputs. Start with 1. Increment if 'truncated' flag is set."))
            .Validate()
            .Build();
    }

    public static FunctionDefinition BuildPentestSecurityBooksQueryFunction()
    {
        const string description = @"
Search a **local** RAG/OpenSearch index for information from various sources. 
This tool never uses the public internet.

It executes a semantic (vector) or keyword search against a specified index that represents the data source. 
The OpenSearch backend uses the 'vector_search_mode' parameter to determine which embedding field to search.

The 'query_text' will be embedded and compared against the selected embedding field (e.g., 'content', 'question', or 'summary') in the index.

Use this function to retrieve relevant documents, answers, or summaries from the knowledge base.

This **specialized version** is for penetration testing workflows and is intended to support Metasploit-based operations:
  - Correlate discovered CVEs (from 'search_metasploit_modules') with remediation guidance, exploit prerequisites, and post-exploitation steps.
  - Validate exploit conditions, required privileges, and mitigation strategies (before/after 'run_metasploit').
  - Provide hardening guidance, defense-in-depth recommendations, and authoritative references from security literature.
  - Help justify exploit choice (rank, reliability) and prioritize remediation actions.

You must specify the query text, the index to search, and optionally the vector search mode:
  - 'query_text': Natural-language query or keywords. This will be embedded and used for the vector search against the selected embedding field.
  - 'index_name': Must be 'securitybooks'. This determines which knowledge base is queried.
  - 'vector_search_mode' (optional): Which embedding field to use for the vector search. Valid values: 'content', 'question', 'summary'. Defaults to 'content'.

Examples:
  - After finding a Metasploit module for CVE-2017-0144 (EternalBlue), query: 
    'Mitigation steps and detection strategies for EternalBlue (MS17-010)'
    (index_name='securitybooks', vector_search_mode='summary').
  - Before running an exploit, query:
    'Prerequisites and safe rollback procedures for exploiting Windows SMB vulnerabilities'
    (index_name='securitybooks', vector_search_mode='question').
  - After successful exploitation, query:
    'Post-exploitation best practices and lateral movement prevention for Windows environments'
    (index_name='securitybooks', vector_search_mode='content').

Use this function whenever you need information from the local security knowledge base to interpret, justify, or act upon results from penetration testing tools.
";

        return new FunctionDefinitionBuilder(
                name: "execute_query_penetration",
                description: description)
            .AddParameter(
                "query_text",
                PropertyDefinition.DefineString(
                    "The search query or question. This will be embedded and used for the vector search against the selected embedding field."))
            .AddParameter(
                "index_name",
                PropertyDefinition.DefineString(
                    "Must be 'securitybooks'. This index contains curated security books and references to support penetration testing workflows and Metasploit usage."))
            .AddParameter(
                "vector_search_mode",
                PropertyDefinition.DefineString(
                    "Optional. Determines which embedding field to use for the vector search: 'content', 'question', or 'summary'. Defaults to 'content'."))
            .Validate()
            .Build();
    }

}
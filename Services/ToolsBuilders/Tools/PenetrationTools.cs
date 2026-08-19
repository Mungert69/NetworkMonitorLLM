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
        return new FunctionDefinition
        {
            Name = "run_metasploit",
            Description = "Executes a Metasploit module with parameter validation. Structure requests as: " +
                          "1. First search modules with search_metasploit_modules " +
                          "2. Get module details with get_metasploit_module_info " +
                          "3. Execute with required parameters. ",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["module_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "[REQUIRED] Full module path from search results. Example: 'exploit/windows/smb/ms17_010_eternalblue'"
                    },
                    ["module_options"] = new PropertyDefinition
                    {
                        Type = "object",
                        Description = "Metasploit module options. Must include RHOSTS and should include only " +
                                      "options confirmed by get_metasploit_module_info. Example: " +
                                      "{ \"RHOSTS\": \"192.168.1.5\", \"RPORT\": 445, \"THREADS\": 1 }"
                    },
                    ["target"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "[REQUIRED] IP/Domain/CIDR range. Validate format first. Example: '192.168.1.0/24'"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Agent location that will run metasploit"
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Output lines to return. Default: 20. Max: 100."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Pagination for large outputs. Start with 1. Increment if 'truncated' flag is set."
                    }
                },
                Required = new List<string> { "module_name", "target", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildSearchMetasploitFunction()
    {
        return new FunctionDefinition
        {
            Name = "search_metasploit_modules",
            Description = "Search modules with filters. Always start penetration tests with this to find appropriate modules. " +
                          "Example: Find Windows SMB exploits: {'module_type':'exploit','platform':'windows','service':'smb'}",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["module_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Category filter. Multiple allowed with commas. Example: 'exploit,auxiliary'"
                    },
                    ["platform"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "OS filter. Use 'multi' for cross-platform"
                    },
                    ["service"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Affected service filter"
                    },
                    ["cve"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "CVE ID with validation. Format: CVE-YYYY-NNNNN. Example: CVE-2017-0144"
                    },
                    ["edb"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Exploit-DB ID. Must be numeric. Example: 42315"
                    },
                    ["rank"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Minimum reliability rating. Default: 'good'"
                    },
                    ["keywords"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Space-separated search terms. Example: 'exchange privilege escalation'"
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Results per page. Default: 10. Max: 50."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Pagination control. Start with 1. Increment if 'more_results'=true"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Agent location that will run the search."
                    }
                },
                Required = new List<string> { "keywords", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildMetasploitModuleInfoFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_metasploit_module_info",
            Description = "Get module requirements BEFORE execution. Required step between search and run. " +
                          "Example: {'module_name':'exploit/windows/smb/ms17_010_eternalblue'}",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["module_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "[REQUIRED] Exact module path from search results. Case-sensitive."
                    },
                    ["show_options"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Include full parameter details. Default: true"
                    },
                    ["show_examples"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Include usage examples. Default: true"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Agent location that will provide the module info."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Output lines to return. Default: 20. Max: 100."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Pagination for large outputs. Start with 1. Increment if 'truncated' flag is set."
                    }
                },
                Required = new List<string> { "module_name", "agent_location" }
            }
        };
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
  - 'vector_search_mode' (optional): Which embedding field to use for the vector search. Valid values: 'content', 'question', 'summary'.
    Recommended for this tool:
    - Start with 'summary' for exploit-selection strategy and mitigation context.
    - Use 'content' when you need exact module/procedure detail for metasploit execution.
    - Use 'question' for direct Q/A style lookups.

Examples:
  - After finding a Metasploit module for CVE-2017-0144 (EternalBlue), query: 
    'Mitigation steps and detection strategies for EternalBlue (MS17-010)'
    (vector_search_mode='summary').
  - Before running an exploit, query:
    'Prerequisites and safe rollback procedures for exploiting Windows SMB vulnerabilities'
    (vector_search_mode='question').
  - After successful exploitation, query:
    'Post-exploitation best practices and lateral movement prevention for Windows environments'
    (vector_search_mode='content').

Use this function whenever you need information from the local security knowledge base to interpret, justify, or act upon results from penetration testing tools.
";

        return new FunctionDefinition
        {
            Name = "execute_query_penetration",
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
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Embedding lane to search: content, question, or summary. Recommended: start with summary; switch to content for exact module/procedure detail; use question for direct Q/A lookups."
                    }
                },
                Required = new List<string> { "query_text", "vector_search_mode" }
            }
        };
    }
}

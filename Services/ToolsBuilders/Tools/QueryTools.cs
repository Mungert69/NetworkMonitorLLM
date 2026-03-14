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

public static class QueryTools
{
    public static FunctionDefinition BuildQueryFunction()
    {
        const string description = @"
Search the Local RAG index for information from various sources. 
This tool does not use the public internet.

It executes a semantic (vector) or keyword search against a specified index that represents the data source. 
The OpenSearch backend uses the 'vector_search_mode' parameter to determine which embedding field to search.

The 'query_text' will be embedded and compared against the selected embedding field (e.g., 'content', 'question', or 'summary') in the index.

Use this function to retrieve relevant documents, answers, or summaries from the knowledge base.

You must specify the query text, the index to search, and optionally the vector search mode.
  - 'query_text': Natural-language query or keywords. This will be embedded and used for the vector search against the selected embedding field.
  - 'index_name': The name of the index to search. This determines which knowledge base or document set is queried. Examples: Use 'documents' to search general FAQs and user help, 'mitre' to search the MITRE ATT&CK document set, or 'securitybooks' for a selection of security books.
  - 'vector_search_mode' (optional): Determines which embedding field to use for the vector search. Valid values: 'content', 'question', 'summary'. Defaults to 'content'.

Examples:
  - If the query is a question, use 'question'.
  - To search the full content, use 'content'.
  - To search summaries, use 'summary'.

Use this function whenever you need information from the local knowledge base.
";

        return new FunctionDefinition
        {
            Name = "execute_query",
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
                        Description = "The name of the index to search. This determines which knowledge base or document set is queried. " +
                                      "Examples: Use 'documents' to search general FAQs and user help, 'securitybooks' for security related information, 'quantumbooks' for quantum ready and safety related information or 'mitre' to search the MITRE ATT&CK document set."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Determines which embedding field to use for the vector search: 'content', 'question', or 'summary'. Defaults to 'content'. Use 'question' to search the questions, 'content' for full text search, and 'summary' for searching summaries.",
                    },
                    ["user_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. For memory-style indices (for example llm_history_turns), filter results to this user id."
                    },
                    ["session_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. For memory-style indices, filter results to a single session id."
                    },
                    ["top_k"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Number of results to return. Defaults to backend default."
                    },
                    ["include_tool_turns"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Optional. For memory-style indices, include tool-call and tool-response turns. Defaults to false."
                    }
                },
                Required = new List<string> { "query_text", "index_name","vector_search_mode" }
            }
        };
    }

    public static FunctionDefinition BuildMemoryQueryFunction()
    {
        const string description = @"
Retrieve conversation memory from the local memory index.
Use this for prior user/assistant turns and tool-status context, especially when context has been trimmed.
This function does not use the public internet.
";

        return new FunctionDefinition
        {
            Name = "execute_query_memory",
            Description = description,
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The memory lookup query, for example a prior decision, preference, or unresolved task."
                    },
                    ["index_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The memory index name. Use 'llm_history_turns'."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Use 'content' for memory lookup."
                    },
                    ["user_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Filter memory to this user id."
                    },
                    ["session_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional session id filter."
                    },
                    ["top_k"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional maximum results."
                    },
                    ["include_tool_turns"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Optional include tool call/response turns."
                    }
                },
                Required = new List<string> { "query_text", "index_name", "vector_search_mode", "user_id" }
            }
        };
    }

    public static FunctionDefinition BuildFaqQueryFunction()
    {
        return new FunctionDefinition
        {
            Name = "execute_query_faq",
            Description = @"
Search the local FAQ/help index only (documents).
Use this for product help, usage guidance, and general support knowledge.
This function does not use the public internet.
",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Natural-language query for FAQ/help content."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional: content/question/summary. Default content."
                    },
                    ["top_k"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional number of results to return."
                    }
                },
                Required = new List<string> { "query_text", "vector_search_mode" }
            }
        };
    }

    public static FunctionDefinition BuildMitreQueryFunction()
    {
        return new FunctionDefinition
        {
            Name = "execute_query_mitre",
            Description = @"
Search the local MITRE ATT&CK index only (mitre).
Use this for tactic/technique context, detection ideas, and mitigation references.
This function does not use the public internet.
",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Natural-language query for MITRE ATT&CK content."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional: content/question/summary. Default content."
                    },
                    ["top_k"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional number of results to return."
                    }
                },
                Required = new List<string> { "query_text", "vector_search_mode" }
            }
        };
    }

    public static FunctionDefinition BuildSecurityBooksQueryFunction()
    {
        return new FunctionDefinition
        {
            Name = "execute_query_securitybooks",
            Description = @"
Search the local Security Books index only (securitybooks).
Use this for deep technical guidance. This lane supports chunk/doc metadata when available.
This function does not use the public internet.
",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Natural-language query for security book content."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional: content/question/summary. Default content."
                    },
                    ["top_k"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional number of results to return."
                    },
                    ["include_metadata"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Optional. Return locator metadata when available. Default true for this function."
                    },
                    ["anchor_doc_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Anchor follow-up retrieval to a specific doc id."
                    },
                    ["anchor_chunk_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Anchor follow-up retrieval to a specific chunk id."
                    },
                    ["neighbor_window"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Number of neighboring chunks to fetch around the anchor."
                    }
                },
                Required = new List<string> { "query_text", "vector_search_mode" }
            }
        };
    }

    public static FunctionDefinition BuildQuantumBooksQueryFunction()
    {
        return new FunctionDefinition
        {
            Name = "execute_query_quantumbooks",
            Description = @"
Search the local Quantum Books index only (quantumbooks).
Use this for deep technical quantum-readiness guidance. This lane supports chunk/doc metadata when available.
This function does not use the public internet.
",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Natural-language query for quantum book content."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional: content/question/summary. Default content."
                    },
                    ["top_k"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional number of results to return."
                    },
                    ["include_metadata"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Optional. Return locator metadata when available. Default true for this function."
                    },
                    ["anchor_doc_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Anchor follow-up retrieval to a specific doc id."
                    },
                    ["anchor_chunk_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Anchor follow-up retrieval to a specific chunk id."
                    },
                    ["neighbor_window"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Number of neighboring chunks to fetch around the anchor."
                    }
                },
                Required = new List<string> { "query_text", "vector_search_mode" }
            }
        };
    }
}

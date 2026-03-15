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
Generic local RAG search across any index.
This function does not use the public internet.

Use this when the caller must choose the index dynamically.
Inputs:
  - query_text: search text for initial semantic lookup.
  - index_name: target index (for example documents, mitre, securitybooks, quantumbooks).
  - vector_search_mode: embedding lane to search: content, question, or summary.

Follow-up retrieval is supported with locator/filter parameters.
For pure follow-up calls, query_text may be empty if anchor/filter parameters are provided.
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
                        Description = "Embedding lane to search: content, question, or summary.",
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
                    },
                    ["include_metadata"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Optional. Return metadata and actionable locator fields in query_result_v2 payload."
                    },
                    ["anchor_doc_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Anchor follow-up retrieval to a specific document id."
                    },
                    ["anchor_chunk_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Anchor follow-up retrieval to a specific chunk id."
                    },
                    ["neighbor_window"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Neighbor chunk window around the anchor chunk."
                    },
                    ["filter_doc_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a specific doc_id."
                    },
                    ["filter_chunk_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a specific chunk_id."
                    },
                    ["filter_source_file"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a source_file."
                    },
                    ["filter_section_path"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to section_path."
                    },
                    ["filter_page_start"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunks overlapping pages >= this value."
                    },
                    ["filter_page_end"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunks overlapping pages <= this value."
                    },
                    ["filter_chunk_index_min"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunk_index >= this value."
                    },
                    ["filter_chunk_index_max"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunk_index <= this value."
                    }
                },
                Required = new List<string> { "query_text", "index_name","vector_search_mode" }
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
                        Description = "Embedding lane to search: content, question, or summary. Use content unless you have a specific reason."
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
                        Description = "Embedding lane to search: content, question, or summary. Use content unless you have a specific reason."
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
For follow-up retrieval, use anchor_doc_id/anchor_chunk_id/neighbor_window or filter_* fields from prior query_result_v2 actionable metadata.
This function does not use the public internet.
For pure follow-up calls, query_text may be empty if anchor/filter parameters are provided.
",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Initial search text for security book content. For follow-up locator/filter calls, this can be empty."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Embedding lane to search: content, question, or summary. Use content unless you have a specific reason."
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
                    },
                    ["filter_doc_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a specific doc_id."
                    },
                    ["filter_chunk_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a specific chunk_id."
                    },
                    ["filter_source_file"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a source_file."
                    },
                    ["filter_section_path"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to section_path."
                    },
                    ["filter_page_start"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunks overlapping pages >= this value."
                    },
                    ["filter_page_end"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunks overlapping pages <= this value."
                    },
                    ["filter_chunk_index_min"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunk_index >= this value."
                    },
                    ["filter_chunk_index_max"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunk_index <= this value."
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
For follow-up retrieval, use anchor_doc_id/anchor_chunk_id/neighbor_window or filter_* fields from prior query_result_v2 actionable metadata.
This function does not use the public internet.
For pure follow-up calls, query_text may be empty if anchor/filter parameters are provided.
",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["query_text"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Initial search text for quantum book content. For follow-up locator/filter calls, this can be empty."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Embedding lane to search: content, question, or summary. Use content unless you have a specific reason."
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
                    },
                    ["filter_doc_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a specific doc_id."
                    },
                    ["filter_chunk_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a specific chunk_id."
                    },
                    ["filter_source_file"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to a source_file."
                    },
                    ["filter_section_path"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Restrict retrieval to section_path."
                    },
                    ["filter_page_start"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunks overlapping pages >= this value."
                    },
                    ["filter_page_end"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunks overlapping pages <= this value."
                    },
                    ["filter_chunk_index_min"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunk_index >= this value."
                    },
                    ["filter_chunk_index_max"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "Optional. Restrict retrieval to chunk_index <= this value."
                    }
                },
                Required = new List<string> { "query_text", "vector_search_mode" }
            }
        };
    }
}

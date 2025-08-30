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
Search a **local** RAG/OpenSearch index for information from various sources. 
This tool never uses the public internet.

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
                                      "Examples: Use 'documents' to search general FAQs and user help, 'mitre' to search the MITRE ATT&CK document set, or 'securitybooks' for a selection of security books."
                    },
                    ["vector_search_mode"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Determines which embedding field to use for the vector search: 'content', 'question', or 'summary'. Defaults to 'content'."
                    }
                },
                Required = new List<string> { "query_text", "index_name","vector_search_mode" }
            }
        };
    }
}

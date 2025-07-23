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
        return new FunctionDefinitionBuilder(
                "execute_query",
                "Executes a semantic or keyword search against a specified index. " +
                "The OpenSearch backend uses the 'vector_search_mode' parameter to determine which embedding field to search. " +
                "The 'query_text' will be embedded and compared against the selected embedding field (e.g., 'content', 'question', or 'summary') in the index. " +
                "Use this function to retrieve relevant documents, answers, or summaries from the knowledge base. " +
                "You must specify the query text, the index to search, and optionally the vector search mode. " +
                "Examples: If the query is a question, use 'question'. To search the full content, use 'content'. To search summaries, use 'summary'.")
            .AddParameter(
                "query_text",
                PropertyDefinition.DefineString(
                    "The search query or question. This will be embedded and used for the vector search against the selected embedding field."))
             .AddParameter(
                "index_name",
                PropertyDefinition.DefineString(
                    "The name of the index to search. This determines which knowledge base or document set is queried. " +
                    "Examples: Use 'documents' to search general FAQs and user help, 'mitre' to search the MITRE ATT&CK document set, or 'securitybooks' for a selection of security books."))
              .AddParameter(
                "vector_search_mode",
                PropertyDefinition.DefineString(
                    "Optional. Determines which embedding field to use for the vector search. " +
                    "Valid values: 'content', 'question', 'summary'. " +
                    "The query_text will be compared against the selected field's embeddings. " +
                    "Defaults to 'content' if not specified. " +
                    "Examples: Use 'question' if the query is a question, 'content' to search the full content, or 'summary' to search summaries."))
            .Validate()
            .Build();
    }
}
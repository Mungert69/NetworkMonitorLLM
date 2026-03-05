using System.Collections.Generic;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services;

public static class MemoryQueryTools
{
    public static FunctionDefinition BuildMemoryQueryFunction()
    {
        const string description = @"
Search conversation memory for facts that may have fallen out of current context.
Use this when you need prior conversation details for the same user or session.
The backend applies defaults and scoping; provide only what is necessary.
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
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "What you want to recall from memory in natural language."
                    },
                    ["top_k"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Optional max number of memory items to return."
                    },
                    ["session_only"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Optional. True to search only the current session; false to search all user memory."
                    }
                },
                Required = new List<string> { "message" }
            }
        };
    }

    public static FunctionDefinition BuildMemoryTurnWindowFunction()
    {
        const string description = @"
Fetch surrounding turns for a known memory hit to recover local conversation context.
Use this after execute_query_memory when you need more detail around a specific turn.
This is a deterministic lookup by session_id and turn_index (no embedding call).
";

        return new FunctionDefinition
        {
            Name = "get_memory_turn_window",
            Description = description,
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["session_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Session identifier from memory query results."
                    },
                    ["turn_index"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Matched turn index from memory query results."
                    },
                    ["width_before"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Optional number of turns before the target turn."
                    },
                    ["width_after"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Optional number of turns after the target turn."
                    }
                },
                Required = new List<string> { "session_id", "turn_index" }
            }
        };
    }
}

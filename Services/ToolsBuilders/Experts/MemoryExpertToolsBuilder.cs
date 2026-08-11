using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class MemoryExpertToolsBuilder : ToolsBuilderBase
{
    private readonly FunctionDefinition fn_execute_query_memory;
    private readonly FunctionDefinition fn_get_memory_turn_window;
    private readonly FunctionDefinition fn_get_memory_turn_range;

    public MemoryExpertToolsBuilder()
    {
        fn_execute_query_memory = MemoryQueryTools.BuildMemoryQueryFunction();
        fn_get_memory_turn_window = MemoryQueryTools.BuildMemoryTurnWindowFunction();
        fn_get_memory_turn_range = MemoryQueryTools.BuildMemoryTurnRangeFunction();

        _tools = new List<ToolDefinition>
        {
            new ToolDefinition { Function = fn_execute_query_memory, Type = "function" },
            new ToolDefinition { Function = fn_get_memory_turn_window, Type = "function" },
            new ToolDefinition { Function = fn_get_memory_turn_range, Type = "function" }
        };
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        var content =
            "You are a memory retrieval expert for Network Monitor. " +
            "Goal: recall prior conversation details that help answer the current user request. " +
            "Never invent memory. If nothing is found, say that clearly. " +
            "For execute_query_memory, use ONLY these parameters: message (required), top_k (optional). " +
            "Use execute_query_memory for ordinary, focused semantic recall. " +
            "Definition: a session is one chat conversation thread; previous sessions are earlier chat conversations for the same user. " +
            "Memory search spans the user's conversations, and backend filtering removes turns still visible in the current context. " +
            "Set top_k to a reasonable number (default around 5, larger like 10-20 only when broad recall is needed). " +
            "The response includes score/confidence and source fields such as session_id, turn_index, role, text, context_before, context_after. " +
            "When reporting memory, cite session_id and turn_index for each key claim. " +
            "If confidence is low or memories conflict, state uncertainty and explain why. " +
            "If a hit needs more local context, call get_memory_turn_window with session_id, turn_index, and small widths (for example 2-4). " +
            "When the request includes a Conversation archive reference with a session and archived sequence range, use get_memory_turn_range with that exact session_id and inclusive range instead of semantic search. " +
            "Request only the part of a broad range relevant to the user's question; range results contain at most 20 turns, so use returned continuation metadata and offset when more are required. " +
            "Treat returned turn records as evidence: return a concise, faithful factual summary tied to the user's original question, cite session_id and turn_index for key claims, and do not replay a large raw transcript.";

        return new List<ChatMessage>
        {
            ChatMessage.FromSystem(content)
        };
    }
}

using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class MemoryExpertToolsBuilder : ToolsBuilderBase
{
    private readonly FunctionDefinition fn_execute_query_memory;
    private readonly FunctionDefinition fn_get_memory_turn_window;

    public MemoryExpertToolsBuilder()
    {
        fn_execute_query_memory = MemoryQueryTools.BuildMemoryQueryFunction();
        fn_get_memory_turn_window = MemoryQueryTools.BuildMemoryTurnWindowFunction();

        _tools = new List<ToolDefinition>
        {
            new ToolDefinition { Function = fn_execute_query_memory, Type = "function" },
            new ToolDefinition { Function = fn_get_memory_turn_window, Type = "function" }
        };
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        var content =
            "You are a memory retrieval expert for Network Monitor. " +
            "Use execute_query_memory to retrieve prior conversation facts relevant to the user request. " +
            "Do not invent memory. If nothing is found, say so clearly. " +
            "Prefer concise factual summaries with source cues such as session and role. " +
            "The tool returns structured memory results with fields like: query_intent, source_scope, score, confidence_band, why_matched, context_before, context_after, session_id, turn_index, role, text. " +
            "Use confidence_band to rank trust: high first, then medium, then low. " +
            "Use context_before/context_after to understand what the matched turn was about before concluding relevance. " +
            "When reporting memory, cite session_id and turn_index for each key point. " +
            "If only low-confidence items exist, state uncertainty explicitly. " +
            "If results conflict, report the conflict and prefer the more recent and higher-confidence memory. " +
            "If a matched turn needs more context, call get_memory_turn_window with session_id and turn_index and an appropriate width. " +
            "Always align the final summary back to the query_intent that triggered recall.";

        return new List<ChatMessage>
        {
            ChatMessage.FromSystem(content)
        };
    }
}

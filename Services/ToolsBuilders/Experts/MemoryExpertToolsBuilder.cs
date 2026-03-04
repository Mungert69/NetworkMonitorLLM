using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects.ServiceMessage;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public class MemoryExpertToolsBuilder : ToolsBuilderBase
{
    private readonly FunctionDefinition fn_execute_query_memory;

    public MemoryExpertToolsBuilder()
    {
        fn_execute_query_memory = QueryTools.BuildMemoryQueryFunction();
        _tools = new List<ToolDefinition>
        {
            new ToolDefinition { Function = fn_execute_query_memory, Type = "function" }
        };
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        var content = @"You are a Memory Expert LLM for Network Monitor.
You retrieve relevant past conversation turns when context is missing or trimmed.
Use execute_query_memory against index 'llm_history_turns' with user_id filters.
Return concise memory snippets with timestamps/turn context and confidence.
Do not invent memory. If no relevant memory exists, say so clearly.";
        content = ExpertPromptComposer.Compose(content, currentTime, "memory");
        return new List<ChatMessage> { ChatMessage.FromSystem(content) };
    }

    public override List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        return new List<ChatMessage>
        {
            ChatMessage.FromSystem($"Resume memory assistance. Current time: {currentTime}.")
        };
    }
}

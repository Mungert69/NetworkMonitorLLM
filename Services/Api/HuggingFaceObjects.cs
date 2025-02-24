using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;
namespace NetworkMonitor.LLM.Services;

public class HuggingFaceChatResponse
{
    [JsonProperty("object")]
    public string Object { get; set; } = string.Empty; // Maps to "object"

    [JsonProperty("id")]
    public string Id { get; set; } = string.Empty; // Maps to "id"

    [JsonProperty("created")]
    public long Created { get; set; } = 0; // Maps to "created"

    [JsonProperty("model")]
    public string Model { get; set; } = string.Empty; // Maps to "model"

    [JsonProperty("system_fingerprint")]
    public string SystemFingerprint { get; set; } = string.Empty; // Maps to "system_fingerprint"

    [JsonProperty("choices")]
    public List<HuggingFaceChoice> Choices { get; set; } = new List<HuggingFaceChoice>(); // Maps to "choices"

    [JsonProperty("usage")]
    public HuggingFaceUsage Usage { get; set; } = new HuggingFaceUsage(); // Maps to "usage"
}

public class HuggingFaceChoice
{
    [JsonProperty("index")]
    public int Index { get; set; } = 0; // Maps to "index"

    [JsonProperty("message")]
    public HuggingFaceMessage Message { get; set; } = new HuggingFaceMessage(); // Maps to "message"

    [JsonProperty("logprobs")]
    public object? Logprobs { get; set; } = null; // Maps to "logprobs"

    [JsonProperty("finish_reason")]
    public string FinishReason { get; set; } = string.Empty; // Maps to "finish_reason"
}

public class HuggingFaceMessage
{
    [JsonProperty("role")]
    public string Role { get; set; } = string.Empty; // Maps to "role"

    [JsonProperty("content")]
    public string Content { get; set; } = string.Empty; // Maps to "content"

    [JsonIgnore] // Not serialized/deserialized unless you add it explicitly in JSON
    public List<ToolCall> ToolCalls { get; set; } = new List<ToolCall>();
}

public class HuggingFaceUsage
{
    [JsonProperty("prompt_tokens")]
    public int PromptTokens { get; set; } = 0; // Maps to "prompt_tokens"

    [JsonProperty("completion_tokens")]
    public int CompletionTokens { get; set; } = 0; // Maps to "completion_tokens"

    [JsonProperty("total_tokens")]
    public int TotalTokens { get; set; } = 0; // Maps to "total_tokens"
}

public class StreamingChatCompletionChunk
{
    [JsonProperty("id")]
    public string Id { get; set; }
    
    [JsonProperty("choices")]
    public List<StreamingChatChoice> Choices { get; set; }
}

public class StreamingChatChoice
{
    [JsonProperty("delta")]
    public StreamingChatDelta Delta { get; set; }
}

public class StreamingChatDelta
{
    [JsonProperty("content")]
    public string Content { get; set; }
    
    [JsonProperty("tool_calls")]
    public List<ToolCallChunk> ToolCalls { get; set; }
}

public class ToolCallChunk
{
    [JsonProperty("index")]
    public int Index { get; set; }
    
    [JsonProperty("id")]
    public string Id { get; set; }
    
    [JsonProperty("function")]
    public FunctionCallChunk Function { get; set; }
}

public class FunctionCallChunk
{
    [JsonProperty("name")]
    public string Name { get; set; }
    
    [JsonProperty("arguments")]
    public string Arguments { get; set; }
}


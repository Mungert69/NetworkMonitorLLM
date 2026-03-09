using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using System;
using System.Collections.Generic;
using System.Text.Json;
using Newtonsoft.Json;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceChatResponse
{
    [JsonProperty("object")]
    public string Object { get; set; } = string.Empty;

    [JsonProperty("id")]
    public string Id { get; set; } = string.Empty;

    [JsonProperty("created")]
    public long Created { get; set; }

    [JsonProperty("model")]
    public string Model { get; set; } = string.Empty;

    [JsonProperty("system_fingerprint")]
    public string SystemFingerprint { get; set; } = string.Empty;

    [JsonProperty("choices")]
    public List<HuggingFaceChoice> Choices { get; set; } = new();

    [JsonProperty("usage")]
    public HuggingFaceUsage Usage { get; set; } = new();
}

public class HuggingFaceChoice
{
    [JsonProperty("index")]
    public int Index { get; set; }

    [JsonProperty("message")]
    public HuggingFaceMessage Message { get; set; } = new();

    [JsonProperty("logprobs")]
    public object? Logprobs { get; set; }

    [JsonProperty("finish_reason")]
    public string FinishReason { get; set; } = string.Empty;
}

public class HuggingFaceMessage
{
    [JsonProperty("role")]
    public string Role { get; set; } = string.Empty;

    [JsonProperty("content")]
    public string Content { get; set; } = string.Empty;

    [JsonProperty("reasoning_content")]
    public string ReasoningContent { get; set; } = string.Empty;

    [JsonProperty("tool_calls")]
    public List<HuggingFaceToolCallDto>? RawToolCalls { get; set; }

    [JsonIgnore]
    public List<ToolCall> ToolCalls { get; set; } = new();

    public void PopulateToolCallsFromRaw()
    {
        if (RawToolCalls == null || RawToolCalls.Count == 0)
        {
            ToolCalls = new List<ToolCall>();
            return;
        }

        var mapped = new List<ToolCall>(RawToolCalls.Count);
        foreach (var dto in RawToolCalls)
        {
            if (dto == null) continue;

            var functionName = dto.Function?.Name?.Trim() ?? string.Empty;
            var arguments = dto.Function?.GetArgumentsAsString() ?? "{}";
            if (string.IsNullOrWhiteSpace(functionName))
            {
                continue;
            }
            if (!IsValidArgumentsPayload(arguments))
            {
                continue;
            }

            mapped.Add(new ToolCall
            {
                Id = dto.Id,
                Type = string.IsNullOrWhiteSpace(dto.Type) ? "function" : dto.Type,
                FunctionCall = new FunctionCall
                {
                    Name = functionName,
                    Arguments = arguments
                }
            });
        }

        ToolCalls = mapped;
    }

    private static bool IsValidArgumentsPayload(string arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments))
        {
            return false;
        }

        var trimmed = arguments.Trim();
        if (string.Equals(trimmed, "null", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(trimmed);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                || doc.RootElement.ValueKind == JsonValueKind.Array;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

public class HuggingFaceUsage
{
    [JsonProperty("prompt_tokens")]
    public int PromptTokens { get; set; }

    [JsonProperty("completion_tokens")]
    public int CompletionTokens { get; set; }

    [JsonProperty("total_tokens")]
    public int TotalTokens { get; set; }
}

public class StreamingChatCompletionChunk
{
    [JsonProperty("id")]
    public string Id { get; set; } = string.Empty;

    [JsonProperty("choices")]
    public List<StreamingChatChoice> Choices { get; set; } = new();
}

public class StreamingChatChoice
{
    [JsonProperty("delta")]
    public StreamingChatDelta Delta { get; set; } = new();
}

public class StreamingChatDelta
{
    [JsonProperty("content")]
    public string Content { get; set; } = string.Empty;

    [JsonProperty("tool_calls")]
    public List<ToolCallChunk>? ToolCalls { get; set; }
}

public class ToolCallChunk
{
    [JsonProperty("index")]
    public int Index { get; set; }

    [JsonProperty("id")]
    public string Id { get; set; } = string.Empty;

    [JsonProperty("function")]
    public FunctionCallChunk Function { get; set; } = new();
}

public class FunctionCallChunk
{
    [JsonProperty("name")]
    public string Name { get; set; } = string.Empty;

    [JsonProperty("arguments")]
    public string Arguments { get; set; } = string.Empty;
}

public class HuggingFaceToolCallDto
{
    [JsonProperty("id")]
    public string? Id { get; set; }

    [JsonProperty("type")]
    public string? Type { get; set; }

    [JsonProperty("function")]
    public HuggingFaceFunctionCallDto? Function { get; set; }
}

public class HuggingFaceFunctionCallDto
{
    [JsonProperty("name")]
    public string? Name { get; set; }

    [JsonProperty("arguments")]
    public object? Arguments { get; set; }

    public string GetArgumentsAsString()
    {
        if (Arguments == null) return "{}";

        if (Arguments is string raw)
        {
            return string.IsNullOrWhiteSpace(raw) ? "{}" : raw;
        }

        // Some providers return function.arguments as a JSON object/array instead of a JSON string.
        return JsonConvert.SerializeObject(Arguments);
    }
}

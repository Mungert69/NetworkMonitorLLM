using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Newtonsoft.Json;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceObjectsTests
{
    [Fact]
    public void ChatResponse_SerializesAndDeserializes()
    {
        var response = new HuggingFaceChatResponse
        {
            Object = "chat.completion",
            Id = "hf-id",
            Created = 1234,
            Model = "hf-model",
            SystemFingerprint = "fingerprint",
            Choices = new List<HuggingFaceChoice>
            {
                new()
                {
                    Index = 0,
                    FinishReason = "stop",
                    Message = new HuggingFaceMessage
                    {
                        Role = "assistant",
                        Content = "hello"
                    }
                }
            },
            Usage = new HuggingFaceUsage
            {
                PromptTokens = 1,
                CompletionTokens = 2,
                TotalTokens = 3
            }
        };
        response.Choices[0].Message.ToolCalls.Add(new ToolCall
        {
            FunctionCall = new FunctionCall
            {
                Name = "func",
                Arguments = "{}"
            }
        });

        var json = JsonConvert.SerializeObject(response);
        var roundTrip = JsonConvert.DeserializeObject<HuggingFaceChatResponse>(json)!;

        Assert.Equal("chat.completion", roundTrip.Object);
        Assert.Equal("hf-id", roundTrip.Id);
        Assert.Equal("hf-model", roundTrip.Model);
        Assert.Single(roundTrip.Choices);
        Assert.Equal("assistant", roundTrip.Choices[0].Message.Role);
        Assert.Equal("hello", roundTrip.Choices[0].Message.Content);
        Assert.Single(roundTrip.Choices[0].Message.ToolCalls);
        Assert.Equal("func", roundTrip.Choices[0].Message.ToolCalls[0].FunctionCall?.Name);
    }

    [Fact]
    public void StreamingChunk_Defaults()
    {
        var chunk = new StreamingChatCompletionChunk
        {
            Id = "chunk",
            Choices = new List<StreamingChatChoice>
            {
                new()
                {
                    Delta = new StreamingChatDelta
                    {
                        Content = "piece",
                        ToolCalls = new List<ToolCallChunk>
                        {
                            new()
                            {
                                Index = 0,
                                Id = "call",
                                Function = new FunctionCallChunk
                                {
                                    Name = "tool",
                                    Arguments = "{}"
                                }
                            }
                        }
                    }
                }
            }
        };

        Assert.Equal("chunk", chunk.Id);
        Assert.Single(chunk.Choices);
        var delta = chunk.Choices[0].Delta;
        Assert.Equal("piece", delta.Content);
        Assert.Single(delta.ToolCalls);
        Assert.Equal("tool", delta.ToolCalls[0].Function.Name);
    }
}

using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;

using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils;
using NetworkMonitor.LLM.Services;
using Newtonsoft.Json;

using Moq;
using Xunit;
namespace NetworkMonitor.LLM.Services;
public class ChatResponseBuilderTests
{
    private readonly Mock<ILLMResponseProcessor> _mockResponseProcessor;
    private readonly Mock<ITokenBroadcaster> _mockTokenBroadcaster;
    private readonly Mock<ILogger> _mockLogger;
    private readonly LLMConfig _config;

    public ChatResponseBuilderTests()
    {
        _mockResponseProcessor = new Mock<ILLMResponseProcessor>();
        _mockTokenBroadcaster = new Mock<ITokenBroadcaster>();
        _mockLogger = new Mock<ILogger>();
        _config = new LLMConfig
        {
            ThinkBeginToken = "<think>",
            ThinkEndToken = "</think>",
            CreateBroadcaster = (rp, logger, xml) => _mockTokenBroadcaster.Object
        };
    }

    private ChatResponseBuilder CreateBuilder(bool isXml = false)
    {
        return new ChatResponseBuilder(_mockResponseProcessor.Object, _config, isXml, _mockLogger.Object);
    }

    [Fact]
    public void BuildResponseFromOpenAI_ParsesFunctionCallsAndSetsToolCalls()
    {
        // Arrange
        var openAIResponse = new ChatCompletionCreateResponse
        {
            Choices = new List<ChatChoiceResponse>
            {
                new ChatChoiceResponse
                {
                    Message = new ChatMessage
                    {
                        Content = "Some <function_call name=\"foo\"><parameters><bar>baz</bar></parameters></function_call> text"
                    }
                }
            }
        };

        _mockTokenBroadcaster
            .Setup(b => b.ParseInputForXml(It.IsAny<string>()))
            .Returns(new List<(string json, string functionName)>
            {
                ("{\"bar\":\"baz\",\"args_escaped\":false}", "foo")
            });

        // Act
        var builder = CreateBuilder();
        var result = builder.BuildResponseFromOpenAI(openAIResponse);

        // Assert
        var toolCalls = result.Choices[0].Message.ToolCalls;
        Assert.NotNull(toolCalls);
        Assert.Single(toolCalls!);
        Assert.Equal("foo", toolCalls![0]!.FunctionCall!.Name);
        Assert.Equal("{\"bar\":\"baz\",\"args_escaped\":false}", toolCalls![0]!.FunctionCall!.Arguments);
    }

    // Helper classes to mock HuggingFaceChatResponse and its choices
    public class DummyHuggingFaceChatResponse
    {
        public List<DummyHuggingFaceChatChoice> Choices { get; set; }
        public DummyHuggingFaceUsage Usage { get; set; }
        public string Id { get; set; }
        public string Model { get; set; }
    }
    public class DummyHuggingFaceChatChoice
    {
        public ChatMessage Message { get; set; }
        public int Index { get; set; }
        public string FinishReason { get; set; }
    }
    public class DummyHuggingFaceUsage
    {
        public int PromptTokens { get; set; }
        public int CompletionTokens { get; set; }
        public int TotalTokens { get; set; }
    }

    [Fact]
    public void BuildResponse_ParsesFunctionCallsAndSetsToolCalls_Xml()
    {
        // Arrange
        var hfResponse = new HuggingFaceChatResponse
        {
            Choices = new List<HuggingFaceChoice>
            {
                new HuggingFaceChoice
                {
                    Message = new HuggingFaceMessage
                    {
                        Role = "assistant",
                        Content = "<function_call name=\"foo\"><parameters><bar>baz</bar></parameters></function_call>"
                    },
                    Index = 0
                }
            },
            Usage = new HuggingFaceUsage { PromptTokens = 1, CompletionTokens = 2, TotalTokens = 3 },
            Id = "id1",
            Model = "model1"
        };

        _mockTokenBroadcaster
            .Setup(b => b.ParseInputForXml(It.IsAny<string>()))
            .Returns(new List<(string json, string functionName)>
            {
                ("{\"bar\":\"baz\",\"args_escaped\":false}", "foo")
            });

        var builder = CreateBuilder(isXml: true);

        // Act
        var result = builder.BuildResponse(hfResponse);

        // Assert
        var toolCalls = result.Choices[0].Message.ToolCalls;
        Assert.NotNull(toolCalls);
        Assert.Single(toolCalls!);
        Assert.Equal("foo", toolCalls![0]!.FunctionCall!.Name);
        Assert.Equal("{\"bar\":\"baz\",\"args_escaped\":false}", toolCalls![0]!.FunctionCall!.Arguments);
        Assert.Equal("tool_calls", result.Choices[0].FinishReason);
        Assert.Equal("id1", result.Id);
        Assert.Equal("model1", result.Model);
        Assert.Equal(1, result.Usage.PromptTokens);
        Assert.Equal(2, result.Usage.CompletionTokens);
        Assert.Equal(3, result.Usage.TotalTokens);
    }

    [Fact]
    public void BuildResponse_ParsesFunctionCallsAndSetsToolCalls_Json()
    {
        // Arrange
        var hfResponse = new HuggingFaceChatResponse
        {
            Choices = new List<HuggingFaceChoice>
            {
                new HuggingFaceChoice
                {
                    Message = new HuggingFaceMessage
                    {
                        Role = "assistant",
                        Content = "{\"foo\": \"bar\"}"
                    },
                    Index = 0
                }
            },
            Usage = new HuggingFaceUsage { PromptTokens = 1, CompletionTokens = 2, TotalTokens = 3 },
            Id = "id2",
            Model = "model2"
        };

        _mockTokenBroadcaster
            .Setup(b => b.ParseInputForJson(It.IsAny<string>()))
            .Returns(new List<(string json, string functionName)>
            {
                ("{\"foo\": \"bar\"}", "myfunc")
            });

        var builder = CreateBuilder(isXml: false);

        // Act
        var result = builder.BuildResponse(hfResponse);

        // Assert
        var toolCalls = result.Choices[0].Message.ToolCalls;
        Assert.NotNull(toolCalls);
        Assert.Single(toolCalls!);
        Assert.Equal("myfunc", toolCalls![0]!.FunctionCall!.Name);
        Assert.Equal("{\"foo\": \"bar\"}", toolCalls![0]!.FunctionCall!.Arguments);
        Assert.Equal("tool_calls", result.Choices[0].FinishReason);
        Assert.Equal("id2", result.Id);
        Assert.Equal("model2", result.Model);
        Assert.Equal(1, result.Usage.PromptTokens);
        Assert.Equal(2, result.Usage.CompletionTokens);
        Assert.Equal(3, result.Usage.TotalTokens);
    }

    [Fact]
    public void BuildResponse_SetsFinishReasonToStop_WhenNoFunctionCalls()
    {
        // Arrange
        var hfResponse = new HuggingFaceChatResponse
        {
            Choices = new List<HuggingFaceChoice>
            {
                new HuggingFaceChoice
                {
                    Message = new HuggingFaceMessage
                    {
                        Role = "assistant",
                        Content = "No function call here"
                    },
                    Index = 0
                }
            },
            Usage = new HuggingFaceUsage { PromptTokens = 1, CompletionTokens = 2, TotalTokens = 3 },
            Id = "id3",
            Model = "model3"
        };

        _mockTokenBroadcaster
            .Setup(b => b.ParseInputForJson(It.IsAny<string>()))
            .Returns(new List<(string json, string functionName)>());

        var builder = CreateBuilder(isXml: false);

        // Act
        var result = builder.BuildResponse(hfResponse);

        // Assert
        // ToolCalls is set to null if there are function calls, otherwise it is an empty list.
        // So, check for empty or null.
        Assert.True(result.Choices[0].Message.ToolCalls == null || !result.Choices[0].Message.ToolCalls!.Any());
        Assert.Equal("stop", result.Choices[0].FinishReason);
    }

    [Fact]
    public void CleanThinking_RemovesThinkingTokens()
    {
        // Arrange
        var builder = CreateBuilder();
        var input = "Hello <think>this is thinking</think> world";
        var method = typeof(ChatResponseBuilder).GetMethod("CleanThinking", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        // Act
        var result = (string)method!.Invoke(builder, new object[] { input })!;

        // Assert
        // The CleanThinking method leaves a double space if the <think>...</think> is in the middle.
        Assert.Equal("Hello  world", result);
    }
}

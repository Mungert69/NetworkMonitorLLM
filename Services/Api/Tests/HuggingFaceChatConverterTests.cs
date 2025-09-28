using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceChatConverterTests
{
    private static LLMConfig CreateConfig() => new()
    {
        UserInputTemplate = "User: {0}",
        AssistantMessageTemplate = "Assistant: {0}",
        AssistantHeader = "Assistant:",
        FunctionResponseTemplate = "Tool name={0} {1}",
        UserReplace = "User:",
        FunctionReplace = "Tool",
        XmlPromptFooter = "<xml-footer>"
    };

    [Fact]
    public void ConvertChatMessagesToPrompt_BuildsExpectedPrompt()
    {
        var config = CreateConfig();
        var messages = new List<ChatMessage>
        {
            ChatMessage.FromUser("hello"),
            ChatMessage.FromAssistant("hi"),
            ChatMessage.FromTool("42", "calculator")
        };

        var prompt = HuggingFaceChatConverter.ConvertChatMessagesToPrompt(messages, config);

        Assert.Contains("User: hello", prompt);
        Assert.Contains("Assistant: hi", prompt);
        Assert.Contains("Tool name=tool 42", prompt);
        Assert.EndsWith(config.AssistantHeader + System.Environment.NewLine, prompt);
    }

    [Fact]
    public void ParseModelOutput_ProducesChatMessages()
    {
        var config = CreateConfig();
        var output = "User: question\nAssistant: answer\nTool name=calculator result";

        var messages = HuggingFaceChatConverter.ParseModelOutput(output, config);

        Assert.Collection(
            messages,
            m => Assert.Equal("user", m.Role),
            m => Assert.Equal("assistant", m.Role),
            m =>
            {
                Assert.Equal("tool", m.Role);
                Assert.Equal("Tool name=calculator result", m.Content);
            });
    }
}

using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class ChatMessageLoggerTests
{
    [Fact]
    public void LogChatMessages_EmitsFormattedTranscript()
    {
        var logger = new Mock<ILogger>();
        var messages = new List<ChatMessage>
        {
            ChatMessage.FromUser("Hello there"),
            new ChatMessage
            {
                Role = "assistant",
                Content = "Here is a result",
                ToolCalls = new List<ToolCall>
                {
                    new()
                    {
                        FunctionCall = new FunctionCall
                        {
                            Name = "lookup",
                            Arguments = "{}"
                        }
                    }
                }
            }
        };

        ChatMessageLogger.LogChatMessages(logger.Object, messages, "Session");

        VerifyLogContains(logger, "--- Session ---");
        VerifyLogContains(logger, "User: Hello there");
        VerifyLogContains(logger, "Assistant: Here is a result");
        VerifyLogContains(logger, "ToolCall - Name: lookup, Arguments: {}");
        VerifyLogContains(logger, "--- End of Session ---");
    }

    [Fact]
    public void LogChatMessages_WhenEmpty_LogsPlaceholder()
    {
        var logger = new Mock<ILogger>();

        ChatMessageLogger.LogChatMessages(logger.Object, new List<ChatMessage>());

        VerifyLogContains(logger, "No chat messages to log.");
    }

    private static void VerifyLogContains(Mock<ILogger> logger, string expected)
    {
        logger.Verify(
            l => l.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((state, _) => state.ToString()!.Contains(expected)),
                It.IsAny<System.Exception?>(),
                It.IsAny<System.Func<It.IsAnyType, System.Exception?, string>>()),
            Times.AtLeastOnce());
    }
}

using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services
{
    public static class ChatMessageLogger
    {
        /// <summary>
        /// Logs a list of ChatMessage objects in a formatted block with message type labels.
        /// </summary>
        /// <param name="logger">The ILogger instance to use for logging.</param>
        /// <param name="messages">The list of ChatMessage objects to log.</param>
        /// <param name="title">Optional title for the log block.</param>
        public static void LogChatMessages(ILogger logger, List<ChatMessage> messages, string title = "Chat Message History")
        {
            if (messages == null || !messages.Any())
            {
                logger.LogInformation("No chat messages to log.");
                return;
            }

            var logBuilder = new StringBuilder();

            logBuilder.AppendLine($"--- {title} ---");
            
            foreach (var message in messages)
            {
                string label = message.Role switch
                {
                    "user" => "User:",
                    "assistant" => "Assistant:",
                    "tool" => "ToolResponse:",
                    _ => "Unknown:"
                };

                logBuilder.AppendLine($"{label} {message.Content}");

                if (message.ToolCalls != null && message.ToolCalls.Any())
                {
                    foreach (var toolCall in message.ToolCalls)
                    {
                        logBuilder.AppendLine($"    ToolCall - Name: {toolCall.FunctionCall?.Name}, Arguments: {toolCall.FunctionCall?.Arguments}");
                    }
                }
            }

            logBuilder.AppendLine($"--- End of {title} ---");

            logger.LogInformation(logBuilder.ToString());
        }
    }
}

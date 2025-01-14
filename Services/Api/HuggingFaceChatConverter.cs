
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils;

namespace NetworkMonitor.LLM.Services;
public static class HuggingFaceChatConverter
{
  
    // Converts a list of ChatMessage objects into a Hugging Face prompt
    public static string ConvertChatMessagesToPrompt(List<ChatMessage> messages, LLMConfig config)
    {
        var promptBuilder = new StringBuilder();

        foreach (var message in messages)
        {
            switch (message.Role)
            {
                case "user":
                    promptBuilder.AppendLine(config.UserInputTemplate.Replace("{0}", message.Content));
                    break;

                case "assistant":
                    promptBuilder.AppendLine(config.AssistantMessageTemplate.Replace("{0}", message.Content));
                    break;

                case "tool":
                    // Add tool responses in the configured format
                    promptBuilder.AppendLine(
                        config.FunctionResponseTemplate
                            .Replace("{0}", message.Name ?? "tool")
                            .Replace("{1}", message.Content ?? ""));
                    break;
            }
        }

        // Add a prompt suffix to instruct the model
        promptBuilder.AppendLine(config.AssistantHeader);
        return promptBuilder.ToString();
    }

    // Parses Hugging Face model output into ChatMessage objects
    public static List<ChatMessage> ParseModelOutput(string output, LLMConfig config)
    {
        var messages = new List<ChatMessage>();
        var lines = output.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            if (line.StartsWith(config.UserReplace))
            {
                messages.Add(ChatMessage.FromUser(line.Replace(config.UserReplace, "").Trim()));
            }
            else if (line.StartsWith(config.AssistantHeader))
            {
                messages.Add(ChatMessage.FromAssistant(line.Replace(config.AssistantHeader, "").Trim()));
            }
            else if (line.StartsWith(config.FunctionReplace))
            {
                // Parse tool responses
                string functionName = ExtractFunctionName(line, config.FunctionResponseTemplate);
                string content = ExtractFunctionContent(line, config.FunctionResponseTemplate);
                messages.Add(ChatMessage.FromTool(content, functionName));
            }
        }

        return messages;
    }

    // Helper to extract the function name from the formatted response
    private static string ExtractFunctionName(string line, string template)
    {
        // Use regex or string manipulation to extract function name
        var match = Regex.Match(line, @"name=(\w+)");
        return match.Success ? match.Groups[1].Value : "unknown";
    }

    // Helper to extract function content from the formatted response
    private static string ExtractFunctionContent(string line, string template)
    {
        // Adjust according to your tool response format
        return line.Replace(template.Split("{1}")[0], "").Trim();
    }
}

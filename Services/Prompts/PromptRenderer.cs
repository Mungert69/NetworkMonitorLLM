using System;
using System.Collections.Generic;
using System.Linq;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services;

public static class PromptRenderer
{
    public static string RenderPromptMessages(LLMConfig config, IReadOnlyList<ChatMessage> messages)
    {
        var builder = new System.Text.StringBuilder();
        string systemTemplate = NormalizeTemplate(config.SystemMessageTemplate);
        string userTemplate = NormalizeTemplate(config.UserInputTemplate);
        string assistantTemplate = NormalizeTemplate(config.AssistantMessageTemplate);
        string functionTemplate = NormalizeTemplate(config.FunctionResponseTemplate);

        foreach (var message in messages)
        {
            if (message == null)
            {
                continue;
            }

            string role = message.Role ?? string.Empty;
            string content = message.Content ?? string.Empty;

            if (role.Equals("system", StringComparison.OrdinalIgnoreCase))
            {
                builder.Append(string.Format(systemTemplate, content));
            }
            else if (role.Equals("user", StringComparison.OrdinalIgnoreCase))
            {
                builder.Append(string.Format(userTemplate, content));
            }
            else if (role.Equals("assistant", StringComparison.OrdinalIgnoreCase))
            {
                string assistantContent = BuildAssistantContent(config, message, content);
                builder.Append(string.Format(assistantTemplate, assistantContent));
            }
            else if (role.Equals("tool", StringComparison.OrdinalIgnoreCase))
            {
                builder.Append(string.Format(functionTemplate, string.Empty, content));
            }
        }

        return builder.ToString();
    }

    public static string BuildToolCallText(LLMConfig config, string functionName, string argumentsJson)
    {
        string args = string.IsNullOrWhiteSpace(argumentsJson) ? "{}" : argumentsJson.Trim();
        string fullJson = $"{{\"name\": \"{functionName}\", \"arguments\": {args}}}";

        if (string.IsNullOrWhiteSpace(config.FunctionBuilder))
        {
            return fullJson;
        }

        string builder = config.FunctionBuilder;

        if (builder.Contains("{0}", StringComparison.Ordinal) || builder.Contains("{1}", StringComparison.Ordinal))
        {
            if (builder.Contains("{0}", StringComparison.Ordinal) && builder.Contains("{1}", StringComparison.Ordinal))
            {
                return string.Format(builder, functionName, args);
            }
            if (builder.Contains("{1}", StringComparison.Ordinal))
            {
                return string.Format(builder, string.Empty, fullJson);
            }

            return string.Format(builder, fullJson);
        }

        return fullJson;
    }

    public static string NormalizeTemplate(string template)
    {
        if (string.IsNullOrEmpty(template))
        {
            return string.Empty;
        }

        return template.Replace("\\\r\n", "\r\n").Replace("\\\n", "\n");
    }

    private static string BuildAssistantContent(LLMConfig config, ChatMessage message, string content)
    {
        var toolCalls = message.ToolCalls;
        if (toolCalls == null || toolCalls.Count == 0)
        {
            return content;
        }

        var toolCallBlocks = new List<string>();
        foreach (var call in toolCalls)
        {
            string name = call.FunctionCall?.Name ?? string.Empty;
            string args = call.FunctionCall?.Arguments ?? "{}";
            string toolCallText = BuildToolCallText(config, name, args);
            toolCallBlocks.Add(toolCallText);
        }

        string toolCallsText = string.Join("\n", toolCallBlocks);
        if (string.IsNullOrWhiteSpace(content))
        {
            return toolCallsText;
        }

        return $"{content}\n{toolCallsText}";
    }
}

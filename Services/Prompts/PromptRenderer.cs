using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
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
        string xmlParameters = BuildXmlParameterBlock(args);
        string argKeyValueXml = BuildArgKeyValueBlock(args);
        string invokeParameters = BuildInvokeParameterBlock(args);

        if (string.IsNullOrWhiteSpace(config.FunctionBuilder))
        {
            return fullJson;
        }

        string builder = config.FunctionBuilder;
        if (!TryRenderNamedTemplate(builder, functionName, args, fullJson, xmlParameters, argKeyValueXml, invokeParameters, out var rendered))
        {
            return fullJson;
        }

        return rendered;
    }

    private static bool TryRenderNamedTemplate(
        string builder,
        string functionName,
        string args,
        string fullJson,
        string xmlParameters,
        string argKeyValueXml,
        string invokeParameters,
        out string rendered)
    {
        rendered = builder;
        var replacements = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["{{function_name}}"] = functionName,
            ["{{arguments_json}}"] = args,
            ["{{tool_call_json}}"] = fullJson,
            ["{{xml_parameters}}"] = xmlParameters,
            ["{{arg_key_values}}"] = argKeyValueXml,
            ["{{invoke_parameters}}"] = invokeParameters
        };

        bool usedNamedToken = false;
        foreach (var (token, value) in replacements)
        {
            if (!rendered.Contains(token, StringComparison.Ordinal))
            {
                continue;
            }

            usedNamedToken = true;
            rendered = rendered.Replace(token, value, StringComparison.Ordinal);
        }

        return usedNamedToken;
    }

    private static string BuildInvokeParameterBlock(string argsJson)
    {
        if (string.IsNullOrWhiteSpace(argsJson))
        {
            return string.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(argsJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return $"<parameter name=\"arguments\">\n{argsJson}\n</parameter>";
            }

            var builder = new StringBuilder();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                string value = property.Value.ValueKind == JsonValueKind.String
                    ? property.Value.GetString() ?? string.Empty
                    : property.Value.GetRawText();

                builder.Append("<parameter name=\"")
                    .Append(property.Name)
                    .Append("\">\n")
                    .Append(value)
                    .Append("\n</parameter>\n");
            }

            return builder.ToString().TrimEnd();
        }
        catch (JsonException)
        {
            return $"<parameter name=\"arguments\">\n{argsJson}\n</parameter>";
        }
    }

    private static string BuildArgKeyValueBlock(string argsJson)
    {
        if (string.IsNullOrWhiteSpace(argsJson))
        {
            return string.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(argsJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return $"<arg_key>arguments</arg_key><arg_value>{argsJson}</arg_value>";
            }

            var builder = new StringBuilder();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                string value = property.Value.ValueKind == JsonValueKind.String
                    ? property.Value.GetString() ?? string.Empty
                    : property.Value.GetRawText();

                builder.Append("<arg_key>")
                    .Append(property.Name)
                    .Append("</arg_key><arg_value>")
                    .Append(value)
                    .Append("</arg_value>");
            }

            return builder.ToString();
        }
        catch (JsonException)
        {
            return $"<arg_key>arguments</arg_key><arg_value>{argsJson}</arg_value>";
        }
    }

    private static string BuildXmlParameterBlock(string argsJson)
    {
        if (string.IsNullOrWhiteSpace(argsJson))
        {
            return string.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(argsJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return $"<parameter=arguments>\n{argsJson}\n</parameter>";
            }

            var builder = new StringBuilder();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                string value = property.Value.ValueKind == JsonValueKind.String
                    ? property.Value.GetString() ?? string.Empty
                    : property.Value.GetRawText();

                builder.Append("<parameter=")
                    .Append(property.Name)
                    .Append(">\n")
                    .Append(value)
                    .Append("\n</parameter>\n");
            }

            return builder.ToString().TrimEnd();
        }
        catch (JsonException)
        {
            return $"<parameter=arguments>\n{argsJson}\n</parameter>";
        }
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

using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace NetworkMonitor.LLM.Services;

internal static class OpenAIWireFormat
{
    private static readonly JsonSerializer NormalizingSerializer = JsonSerializer.Create(new JsonSerializerSettings
    {
        ContractResolver = new CamelCasePropertyNamesContractResolver(),
        NullValueHandling = NullValueHandling.Ignore
    });

    public static string Role(ChatMessage message)
    {
        return message.Role?.ToString() ?? "user";
    }

    public static bool IsRole(ChatMessage message, string role)
    {
        return string.Equals(Role(message), role, StringComparison.OrdinalIgnoreCase);
    }

    public static string ToolCallType(ToolCall toolCall)
    {
        var type = toolCall.Type?.ToString();
        return string.IsNullOrWhiteSpace(type)
            ? "function"
            : type;
    }

    public static string Detail(MessageContent part)
    {
        var detail = part.ImageUrl?.Detail?.ToString();
        return string.IsNullOrWhiteSpace(detail)
            ? "auto"
            : detail;
    }

    public static object? NormalizeJsonValue(object? value)
    {
        if (value == null) return null;
        if (value is string or bool or char) return value;
        if (value is byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal) return value;
        if (value is JToken token) return NormalizeToken(token);

        return NormalizeToken(JToken.FromObject(value, NormalizingSerializer));
    }

    public static object? NormalizeToolParameters(object? parameters)
    {
        return NormalizeJsonValue(parameters);
    }

    public static object BuildStructuredContent(ChatMessage message)
    {
        var parts = ExtractMessageContents(message);
        if (parts.Count == 0)
        {
            return message.Content ?? string.Empty;
        }

        return parts.Select(part =>
        {
            if (string.Equals(part.Type, "image_url", StringComparison.OrdinalIgnoreCase))
            {
                return new Dictionary<string, object?>
                {
                    ["type"] = "image_url",
                    ["image_url"] = new Dictionary<string, object?>
                    {
                        ["url"] = part.ImageUrl?.Url ?? string.Empty,
                        ["detail"] = Detail(part)
                    }
                };
            }

            return new Dictionary<string, object?>
            {
                ["type"] = "text",
                ["text"] = part.Text ?? string.Empty
            };
        }).ToList();
    }

    public static List<MessageContent> ExtractMessageContents(ChatMessage message)
    {
        if (message.ContentCalculated is IList<MessageContent> typedList)
        {
            return typedList.ToList();
        }

        if (message.ContentCalculated is IEnumerable<MessageContent> typedEnumerable)
        {
            return typedEnumerable.ToList();
        }

        return new List<MessageContent>();
    }

    private static JToken NormalizeToken(JToken token)
    {
        if (token is JObject obj)
        {
            if (obj.Count == 1)
            {
                var single = obj.Properties().First();
                if (string.Equals(single.Name, "value", StringComparison.OrdinalIgnoreCase))
                {
                    return NormalizeToken(single.Value);
                }
            }

            var normalized = new JObject();
            foreach (var prop in obj.Properties())
            {
                normalized[prop.Name] = NormalizeToken(prop.Value);
            }

            return normalized;
        }

        if (token is JArray array)
        {
            return new JArray(array.Select(NormalizeToken));
        }

        return token;
    }
}

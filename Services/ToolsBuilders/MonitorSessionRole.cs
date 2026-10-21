using System;

namespace NetworkMonitor.LLM.Services;

/// <summary>Reads an optional role from the conversation component, leaving the ID intact.</summary>
public static class MonitorSessionRole
{
    public static string? FromSessionId(string? sessionId)
    {
        if (string.IsNullOrEmpty(sessionId)) return null;

        // Full IDs are conversation_user_runner. Never inspect user or runner text.
        int end = sessionId.IndexOf('_');
        string conversation = end < 0 ? sessionId : sessionId.Substring(0, end);
        int separator = conversation.LastIndexOf(':');
        if (separator <= 0) return null;

        return conversation.Substring(separator + 1).ToLowerInvariant() switch
        {
            "hal" or "hal9000" => "hal9000",
            "halsimple" or "hal9000simple" => "hal9000simple",
            "standard" => "standard",
            "simple" => "simple",
            _ => null
        };
    }

    internal static string PromptFileName(string fileName, string? sessionId)
    {
        string? role = FromSessionId(sessionId);
        return role == null ? fileName : fileName + "." + role;
    }
}

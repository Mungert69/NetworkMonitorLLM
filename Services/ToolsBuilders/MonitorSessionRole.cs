using System;
using NetworkMonitor.Objects;

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

    internal static string? Resolve(string toolsId, SystemParams systemParams, MLParams settings,
        string? runnerType, string? sessionId)
    {
        if (!string.Equals(toolsId, "monitor", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(systemParams.UserFacingServiceId, "monitor", StringComparison.OrdinalIgnoreCase))
            return null;

        var role = FromSessionId(sessionId);
        if (role != null) return role;
        if (!string.IsNullOrWhiteSpace(runnerType) &&
            settings.PrimaryMonitorRoleByRunner.TryGetValue(runnerType, out var runnerRole) &&
            !string.IsNullOrWhiteSpace(runnerRole))
            return runnerRole;
        return settings.PrimaryMonitorRole;
    }

    internal static bool UsesHalVoice(string? role) => role?.Trim().ToLowerInvariant() is
        "hal" or "hal9000" or "halsimple" or "hal9000simple" or "hal_simple" or "hal9000_simple";

    internal static string PromptFileName(string fileName, string? sessionId)
    {
        string? role = FromSessionId(sessionId);
        return role == null ? fileName : fileName + "." + role;
    }
}

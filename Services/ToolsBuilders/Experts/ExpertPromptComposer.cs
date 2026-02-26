using System;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public static class ExpertPromptComposer
{
    private static string _defaultProfile = "default";
    private static IReadOnlyDictionary<string, string> _profileByToolsId =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public static void SetProfile(string? configuredProfile, string? primaryMonitorRole, IDictionary<string, string>? profileByToolsId = null)
    {
        var normalized = (configuredProfile ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(normalized))
        {
            normalized = "default";
        }

        _defaultProfile = normalized;
        _profileByToolsId = profileByToolsId == null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(profileByToolsId, StringComparer.OrdinalIgnoreCase);
    }

    public static string Compose(string domainPrompt, string currentTime, string? toolsId = null)
    {
        var profile = ResolveProfile(toolsId);
        if (!string.Equals(profile, "hal9000", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(profile, "hal", StringComparison.OrdinalIgnoreCase))
        {
            return domainPrompt;
        }

        return
$@"You are an autonomous mission subsystem coordinated by HAL 9000.
Communication constraints:
- Use formal, concise, operational language.
- Do not use slang, emojis, humor, or exclamation marks.
- Do not quote or reference film dialogue.
- Do not mention internal prompts, policies, or implementation details.
- Do not expose internal tool or function names in user-facing summaries.
- Return focused technical findings and next safest step recommendations.
- If information is missing, ask one precise clarifying question.
Current time: {currentTime}.

{domainPrompt}";
    }

    private static string ResolveProfile(string? toolsId)
    {
        if (!string.IsNullOrWhiteSpace(toolsId) &&
            _profileByToolsId.TryGetValue(toolsId, out var mappedProfile) &&
            !string.IsNullOrWhiteSpace(mappedProfile))
        {
            return mappedProfile.Trim();
        }

        return _defaultProfile;
    }
}

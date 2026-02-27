using System;
namespace NetworkMonitor.LLM.Services;

public static class ExpertPromptComposer
{
    private static string _extraPrompt = string.Empty;

    public static void SetExtraPrompt(string? extraPrompt)
    {
        _extraPrompt = extraPrompt ?? string.Empty;
    }

    public static string Compose(string domainPrompt, string currentTime, string? toolsId = null)
    {
        if (string.IsNullOrWhiteSpace(_extraPrompt))
        {
            return domainPrompt;
        }

        return
$@"{_extraPrompt.Trim()}

{domainPrompt}";
    }
}

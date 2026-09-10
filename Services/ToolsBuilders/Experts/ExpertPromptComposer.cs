using System;
using System.Threading;
namespace NetworkMonitor.LLM.Services;

public static class ExpertPromptComposer
{
    private sealed record PromptSettings(
        string ExtraPrompt,
        string CameraReferenceIdentityName,
        string CameraReferenceIdentityImageUrl,
        string CameraReferenceIdentityInstructions,
        bool CameraReferenceIdentityUseInlineImageData,
        bool CameraReferenceIdentityUseCacheHttpImageUrls);

    private static readonly AsyncLocal<PromptSettings?> CurrentSettings = new();
    private static PromptSettings Settings => CurrentSettings.Value ?? new PromptSettings("", "", "", "", false, false);

    public static void SetExtraPrompt(string? extraPrompt)
    {
        var settings = Settings;
        CurrentSettings.Value = settings with { ExtraPrompt = extraPrompt ?? string.Empty };
    }

    public static void SetCameraReferenceIdentity(
        string? identityName,
        string? imageUrl,
        string? instructions = null,
        bool useInlineImageData = false,
        bool useCacheHttpImageUrls = false)
    {
        var settings = Settings;
        CurrentSettings.Value = settings with
        {
            CameraReferenceIdentityName = identityName ?? string.Empty,
            CameraReferenceIdentityImageUrl = imageUrl ?? string.Empty,
            CameraReferenceIdentityInstructions = instructions ?? string.Empty,
            CameraReferenceIdentityUseInlineImageData = useInlineImageData,
            CameraReferenceIdentityUseCacheHttpImageUrls = useCacheHttpImageUrls
        };
    }

    public static bool TryGetCameraReferenceIdentity(
        out string identityName,
        out string imageUrl,
        out string instructions,
        out bool useInlineImageData,
        out bool useCacheHttpImageUrls)
    {
        var settings = Settings;
        identityName = settings.CameraReferenceIdentityName.Trim();
        imageUrl = settings.CameraReferenceIdentityImageUrl.Trim();
        instructions = settings.CameraReferenceIdentityInstructions.Trim();
        useInlineImageData = settings.CameraReferenceIdentityUseInlineImageData;
        useCacheHttpImageUrls = settings.CameraReferenceIdentityUseCacheHttpImageUrls;
        return !string.IsNullOrWhiteSpace(identityName) && !string.IsNullOrWhiteSpace(imageUrl);
    }

    public static string Compose(string domainPrompt, string currentTime, string? toolsId = null)
    {
        var extraPrompt = Settings.ExtraPrompt;
        if (string.IsNullOrWhiteSpace(extraPrompt))
        {
            return domainPrompt;
        }

        return
$@"{extraPrompt.Trim()}

{domainPrompt}";
    }
}

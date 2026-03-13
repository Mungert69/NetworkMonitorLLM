using System;
namespace NetworkMonitor.LLM.Services;

public static class ExpertPromptComposer
{
    private static string _extraPrompt = string.Empty;
    private static string _cameraReferenceIdentityName = string.Empty;
    private static string _cameraReferenceIdentityImageUrl = string.Empty;
    private static string _cameraReferenceIdentityInstructions = string.Empty;
    private static bool _cameraReferenceIdentityUseInlineImageData = false;
    private static bool _cameraReferenceIdentityUseCacheHttpImageUrls = false;

    public static void SetExtraPrompt(string? extraPrompt)
    {
        _extraPrompt = extraPrompt ?? string.Empty;
    }

    public static void SetCameraReferenceIdentity(
        string? identityName,
        string? imageUrl,
        string? instructions = null,
        bool useInlineImageData = false,
        bool useCacheHttpImageUrls = false)
    {
        _cameraReferenceIdentityName = identityName ?? string.Empty;
        _cameraReferenceIdentityImageUrl = imageUrl ?? string.Empty;
        _cameraReferenceIdentityInstructions = instructions ?? string.Empty;
        _cameraReferenceIdentityUseInlineImageData = useInlineImageData;
        _cameraReferenceIdentityUseCacheHttpImageUrls = useCacheHttpImageUrls;
    }

    public static bool TryGetCameraReferenceIdentity(
        out string identityName,
        out string imageUrl,
        out string instructions,
        out bool useInlineImageData,
        out bool useCacheHttpImageUrls)
    {
        identityName = _cameraReferenceIdentityName.Trim();
        imageUrl = _cameraReferenceIdentityImageUrl.Trim();
        instructions = _cameraReferenceIdentityInstructions.Trim();
        useInlineImageData = _cameraReferenceIdentityUseInlineImageData;
        useCacheHttpImageUrls = _cameraReferenceIdentityUseCacheHttpImageUrls;
        return !string.IsNullOrWhiteSpace(identityName) && !string.IsNullOrWhiteSpace(imageUrl);
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

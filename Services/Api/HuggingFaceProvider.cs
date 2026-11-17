// File: Services/Api/HuggingFaceProvider.cs
using System;

namespace NetworkMonitor.LLM.Services;

/// <summary>
/// Upstream providers that can be reached through the HuggingFace / OpenAI compatible HTTP API.
/// The provider decides which provider specific request fields are valid.
/// </summary>
public enum HuggingFaceProvider
{
    /// <summary>Provider could not be determined, no provider specific extras are sent.</summary>
    Unknown = 0,

    /// <summary>OpenRouter (https://openrouter.ai). Supports provider routing preferences.</summary>
    OpenRouter,

    /// <summary>Novita AI (https://api.novita.ai). Does not accept the OpenRouter provider block.</summary>
    Novita,

    /// <summary>Hugging Face inference endpoints (https://huggingface.co / api-inference).</summary>
    HuggingFace
}

/// <summary>
/// Resolves which upstream provider is used for a HuggingFace style request and
/// exposes the capabilities of that provider.
/// </summary>
public static class HuggingFaceProviderResolver
{
    public const string Auto = "Auto";

    /// <summary>
    /// Resolve the provider. An explicit configured value always wins, otherwise the
    /// provider is detected from the API url.
    /// </summary>
    public static HuggingFaceProvider Resolve(string? configuredProvider, string? apiUrl)
    {
        var configured = ParseProvider(configuredProvider);
        if (configured.HasValue)
        {
            return configured.Value;
        }

        return DetectFromUrl(apiUrl);
    }

    /// <summary>
    /// OpenRouter accepts a "provider" block used to steer provider routing.
    /// Other providers reject the unknown field, so it must only be sent to OpenRouter.
    /// </summary>
    public static bool SupportsProviderRouting(HuggingFaceProvider provider)
    {
        return provider == HuggingFaceProvider.OpenRouter;
    }

    public static string Describe(HuggingFaceProvider provider)
    {
        return provider switch
        {
            HuggingFaceProvider.OpenRouter => "OpenRouter",
            HuggingFaceProvider.Novita => "Novita",
            HuggingFaceProvider.HuggingFace => "HuggingFace",
            _ => "Unknown"
        };
    }

    private static HuggingFaceProvider? ParseProvider(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Equals(Auto, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (trimmed.Equals("OpenRouter", StringComparison.OrdinalIgnoreCase))
        {
            return HuggingFaceProvider.OpenRouter;
        }

        if (trimmed.Equals("Novita", StringComparison.OrdinalIgnoreCase))
        {
            return HuggingFaceProvider.Novita;
        }

        if (trimmed.Equals("HuggingFace", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("Hugging Face", StringComparison.OrdinalIgnoreCase))
        {
            return HuggingFaceProvider.HuggingFace;
        }

        if (trimmed.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("None", StringComparison.OrdinalIgnoreCase))
        {
            return HuggingFaceProvider.Unknown;
        }

        return null;
    }

    private static HuggingFaceProvider DetectFromUrl(string? apiUrl)
    {
        if (string.IsNullOrWhiteSpace(apiUrl))
        {
            return HuggingFaceProvider.Unknown;
        }

        if (!Uri.TryCreate(apiUrl, UriKind.Absolute, out var uri))
        {
            // Fall back to a simple host match for urls that are not valid absolute uris.
            var lowered = apiUrl.ToLowerInvariant();
            if (lowered.Contains("openrouter.ai")) return HuggingFaceProvider.OpenRouter;
            if (lowered.Contains("novita.ai")) return HuggingFaceProvider.Novita;
            if (lowered.Contains("huggingface.co") || lowered.Contains("api-inference")) return HuggingFaceProvider.HuggingFace;
            return HuggingFaceProvider.Unknown;
        }

        var host = uri.Host.ToLowerInvariant();
        if (host.Equals("openrouter.ai", StringComparison.Ordinal) || host.EndsWith(".openrouter.ai", StringComparison.Ordinal))
        {
            return HuggingFaceProvider.OpenRouter;
        }

        if (host.Equals("novita.ai", StringComparison.Ordinal) || host.EndsWith(".novita.ai", StringComparison.Ordinal))
        {
            return HuggingFaceProvider.Novita;
        }

        if (host.Equals("huggingface.co", StringComparison.Ordinal) || host.EndsWith(".huggingface.co", StringComparison.Ordinal))
        {
            return HuggingFaceProvider.HuggingFace;
        }

        if (uri.AbsolutePath.Contains("api-inference", StringComparison.OrdinalIgnoreCase))
        {
            return HuggingFaceProvider.HuggingFace;
        }

        return HuggingFaceProvider.Unknown;
    }
}

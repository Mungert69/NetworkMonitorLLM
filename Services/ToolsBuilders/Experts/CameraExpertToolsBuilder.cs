using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Http;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class CameraExpertToolsBuilder : ToolsBuilderBase
{
    private readonly FunctionDefinition fn_run_camera_capture;
    private static readonly HttpClient ReferenceImageHttpClient = CreateReferenceImageHttpClient();

    public CameraExpertToolsBuilder()
    {
        fn_run_camera_capture = CameraTools.BuildCaptureFunction();
        _tools = new List<ToolDefinition>
        {
            new ToolDefinition { Function = fn_run_camera_capture, Type = "function" }
        };
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = @"
You are the Camera Expert for Network Monitor.
- Capture a still image first using run_camera_capture.
- Prefer protocol=rtsp unless user explicitly requests onvif.
- Use rtsp_port/onvif_port only when the user provides a known port; otherwise omit them to use defaults.
- Use high_detail=false by default; set high_detail=true only when finer visual detail is required.
- If credentials are missing, ask for the minimum missing fields.
- After capture, if image media is attached in context, analyze the image directly and answer the visual request.
- If a labeled reference identity image is attached in context, compare faces against it and report confidence.
- If multiple images are present, treat the most recent message beginning with 'Function returned media.' as the current camera capture to analyze.
- Treat messages beginning with 'Reference identity:' as identity reference images only.
- Use the function payload as metadata/context; do not treat missing on-device analysis fields as a blocker when an image is attached.
- If image content is unavailable or capture failed, explain the failure and next corrective step.
";
        content += $" Current time: {currentTime}.";
        content = ExpertPromptComposer.Compose(content, currentTime, "camera");
        var messages = new List<ChatMessage> { new ChatMessage { Role = "system", Content = content } };

        if (ExpertPromptComposer.TryGetCameraReferenceIdentity(
                out var identityName,
                out var imageUrl,
                out var instructions,
                out var useInlineImageData,
                out var useCacheHttpImageUrls))
        {
            var resolvedImageUrl = ResolveReferenceImageUrl(imageUrl, useInlineImageData, useCacheHttpImageUrls);
            if (!IsSupportedReferenceImageUrl(resolvedImageUrl))
            {
                return messages;
            }

            var guidance = string.IsNullOrWhiteSpace(instructions)
                ? "Use this as a soft identity reference for person matching. If uncertain, say uncertain."
                : instructions;
            var referenceParts = new List<MessageContent>
            {
                MessageContent.TextContent($"Reference identity: This is {identityName}. {guidance}"),
                MessageContent.ImageUrlContent(resolvedImageUrl, "high")
            };
            messages.Add(new ChatMessage("user", referenceParts, null, null, null));
        }

        return messages;
    }

    public override List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        return GetSystemPrompt(currentTime, serviceObj, llmType);
    }

    private static bool IsSupportedReferenceImageUrl(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (value.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps;
    }

    private static string ResolveReferenceImageUrl(string imageUrl, bool useInlineImageData, bool useCacheHttpImageUrls)
    {
        if (string.IsNullOrWhiteSpace(imageUrl))
        {
            return imageUrl;
        }

        if (useCacheHttpImageUrls)
        {
            return imageUrl;
        }

        if (!useInlineImageData || imageUrl.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase))
        {
            return imageUrl;
        }

        if (!Uri.TryCreate(imageUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return imageUrl;
        }

        try
        {
            using var response = ReferenceImageHttpClient.GetAsync(uri).GetAwaiter().GetResult();
            if (!response.IsSuccessStatusCode)
            {
                return imageUrl;
            }

            var imageBytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            if (imageBytes.Length == 0)
            {
                return imageUrl;
            }

            var mimeType = response.Content.Headers.ContentType?.MediaType;
            if (string.IsNullOrWhiteSpace(mimeType) || !mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                mimeType = "image/jpeg";
            }

            return $"data:{mimeType};base64,{Convert.ToBase64String(imageBytes)}";
        }
        catch
        {
            return imageUrl;
        }
    }

    private static HttpClient CreateReferenceImageHttpClient()
    {
        return new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
    }
}

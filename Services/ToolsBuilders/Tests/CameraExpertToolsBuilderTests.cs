using System.Collections.Generic;
using System.Linq;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class CameraExpertToolsBuilderTests
{
    [Fact]
    public void GetSystemPrompt_WithoutReferenceIdentity_ReturnsOnlySystemMessage()
    {
        ExpertPromptComposer.SetCameraReferenceIdentity("", "", "");

        var builder = new CameraExpertToolsBuilder();
        var messages = builder.GetSystemPrompt("2026-03-12T00:00:00", new LLMServiceObj(), "TurboLLM");

        Assert.Single(messages);
        Assert.Equal("system", messages[0].Role);
    }

    [Fact]
    public void GetSystemPrompt_WithReferenceIdentity_AddsMultimodalReferenceMessage()
    {
        ExpertPromptComposer.SetCameraReferenceIdentity(
            "Dave",
            "https://example.com/dave-reference.jpg",
            "Use this for identity comparison.");

        try
        {
            var builder = new CameraExpertToolsBuilder();
            var messages = builder.GetSystemPrompt("2026-03-12T00:00:00", new LLMServiceObj(), "TurboLLM");

            Assert.Equal(2, messages.Count);
            Assert.Equal("system", messages[0].Role);
            Assert.Equal("user", messages[1].Role);

            var parts = messages[1].ContentCalculated as IEnumerable<MessageContent>;
            Assert.NotNull(parts);
            var partList = parts!.ToList();
            Assert.Equal(2, partList.Count);
            Assert.Equal("text", partList[0].Type);
            Assert.Contains("This is Dave", partList[0].Text ?? string.Empty);
            Assert.Equal("image_url", partList[1].Type);
            Assert.Equal("https://example.com/dave-reference.jpg", partList[1].ImageUrl?.Url);
        }
        finally
        {
            ExpertPromptComposer.SetCameraReferenceIdentity("", "", "");
        }
    }

    [Fact]
    public void GetSystemPrompt_WithInlineReferenceIdentityDataUrl_KeepsDataUrl()
    {
        const string dataUrl = "data:image/png;base64,AQID";
        ExpertPromptComposer.SetCameraReferenceIdentity(
            "Dave",
            dataUrl,
            "Use this for identity comparison.",
            useInlineImageData: true);

        try
        {
            var builder = new CameraExpertToolsBuilder();
            var messages = builder.GetSystemPrompt("2026-03-12T00:00:00", new LLMServiceObj(), "TurboLLM");

            Assert.Equal(2, messages.Count);
            var parts = messages[1].ContentCalculated as IEnumerable<MessageContent>;
            Assert.NotNull(parts);
            var partList = parts!.ToList();
            Assert.Equal("image_url", partList[1].Type);
            Assert.Equal(dataUrl, partList[1].ImageUrl?.Url);
        }
        finally
        {
            ExpertPromptComposer.SetCameraReferenceIdentity("", "", "");
        }
    }
}

using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class TextNormalizationHelperTests
{
    [Fact]
    public void NormalizeTextForTTS_StripsMarkdownAndFormatsDate()
    {
        var input = "## Heading\nThis *is* a [link](https://example.com) from 2025-01-13T17:41:00!";
        var logger = new Mock<ILogger>();

        var normalized = TextNormalizationHelper.NormalizeTextForTTS(input, logger.Object);

        Assert.Equal(
            "Heading This is a link to https:example.com from January 13, 2025, at 5:41 pm!",
            normalized);
        logger.Verify(l => l.Log(
            LogLevel.Information,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((state, _) => state.ToString()!.Contains("Normalized Text")),
            It.IsAny<System.Exception?>(),
            It.IsAny<System.Func<It.IsAnyType, System.Exception?, string>>()),
            Times.Once);
    }
}

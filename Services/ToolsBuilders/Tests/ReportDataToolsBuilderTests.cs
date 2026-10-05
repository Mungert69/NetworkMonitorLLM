using NetworkMonitor.Objects.ServiceMessage;
using Xunit;
namespace NetworkMonitor.LLM.Services;
public class ReportDataToolsBuilderTests
{
    [Fact]
    public void ReportPromptUsesCatalogueUnitsKindsAndNullableMissingReadings()
    {
        var prompt=Assert.Single(new ReportDataToolsBuilder().GetSystemPrompt("now",new LLMServiceObj(),"TestLLM")).Content;
        Assert.Contains("measurement_context",prompt);
        Assert.Contains("Only millisecond durations with explicit TimingRatingThresholds contain Category",prompt);
        Assert.Contains("Unrated durations and other measurements have no Category",prompt);
        Assert.Contains("AnalysisGuidance",prompt);
        Assert.Contains("never apply scale or offset again",prompt);
        Assert.Contains("Negative physical values, including -1, can be valid",prompt);
        Assert.Contains("Follow measurement_context.AnalysisGuidance",prompt);
        Assert.Contains("original network performance-analysis instructions",prompt);
        Assert.Contains("Do not apply duration-analysis rules to other measurement kinds",prompt);
        Assert.DoesNotContain("For counters",prompt);
        Assert.DoesNotContain("For continuous measurements",prompt);
        Assert.Contains("performance_assessment",prompt);
        Assert.Contains("expert_recommendations",prompt);
        Assert.DoesNotContain("All response times are measured in milliseconds",prompt);
        Assert.DoesNotContain("Each data point represents a 2-hour",prompt);
    }
}

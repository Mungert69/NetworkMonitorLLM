using Xunit;

namespace NetworkMonitor.LLM.Services;

public class SearchToolsTests
{
    [Fact]
    public void BuildSearchWebFunction_ExposesMicroAndMacroTimeoutParameters()
    {
        var fn = SearchTools.BuildSearchWebFunction();

        Assert.Equal("run_search_web", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.NotNull(fn.Parameters!.Properties);

        Assert.True(fn.Parameters.Properties!.ContainsKey("micro_timeout"));
        Assert.True(fn.Parameters.Properties.ContainsKey("macro_timeout"));
        Assert.Equal("boolean", fn.Parameters.Properties["return_only_urls"].Type);
        Assert.Equal("integer", fn.Parameters.Properties["micro_timeout"].Type);
        Assert.Equal("integer", fn.Parameters.Properties["macro_timeout"].Type);
    }

    [Fact]
    public void BuildCrawlPageFunction_ExposesMicroTimeoutNotTimeout()
    {
        var fn = SearchTools.BuildCrawlPageFunction();

        Assert.Equal("run_crawl_page", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.NotNull(fn.Parameters!.Properties);

        Assert.True(fn.Parameters.Properties!.ContainsKey("micro_timeout"));
        Assert.True(fn.Parameters.Properties.ContainsKey("macro_timeout"));
        Assert.False(fn.Parameters.Properties.ContainsKey("timeout"));
        Assert.Equal("integer", fn.Parameters.Properties["micro_timeout"].Type);
        Assert.Equal("integer", fn.Parameters.Properties["macro_timeout"].Type);
    }
}

using Xunit;

namespace NetworkMonitor.LLM.Services;

public class QueryToolsTests
{
    [Fact]
    public void BuildFaqQueryFunction_UsesDedicatedFunctionName()
    {
        var fn = QueryTools.BuildFaqQueryFunction();

        Assert.Equal("execute_query_faq", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.NotNull(fn.Parameters!.Properties);
        Assert.True(fn.Parameters.Properties!.ContainsKey("query_text"));
        Assert.True(fn.Parameters.Properties.ContainsKey("vector_search_mode"));
        Assert.False(fn.Parameters.Properties.ContainsKey("index_name"));
    }

    [Fact]
    public void BuildMitreQueryFunction_UsesDedicatedFunctionName()
    {
        var fn = QueryTools.BuildMitreQueryFunction();

        Assert.Equal("execute_query_mitre", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.NotNull(fn.Parameters!.Properties);
        Assert.True(fn.Parameters.Properties!.ContainsKey("query_text"));
        Assert.True(fn.Parameters.Properties.ContainsKey("vector_search_mode"));
        Assert.False(fn.Parameters.Properties.ContainsKey("index_name"));
    }

    [Fact]
    public void BuildSecurityBooksQueryFunction_ExposesMetadataLocatorParameters()
    {
        var fn = QueryTools.BuildSecurityBooksQueryFunction();

        Assert.Equal("execute_query_securitybooks", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.NotNull(fn.Parameters!.Properties);

        Assert.True(fn.Parameters.Properties!.ContainsKey("include_metadata"));
        Assert.True(fn.Parameters.Properties.ContainsKey("anchor_doc_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("anchor_chunk_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("neighbor_window"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_doc_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_chunk_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_source_file"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_section_path"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_page_start"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_page_end"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_chunk_index_min"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_chunk_index_max"));
        Assert.False(fn.Parameters.Properties.ContainsKey("index_name"));
    }

    [Fact]
    public void BuildQuantumBooksQueryFunction_ExposesMetadataLocatorParameters()
    {
        var fn = QueryTools.BuildQuantumBooksQueryFunction();

        Assert.Equal("execute_query_quantumbooks", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.NotNull(fn.Parameters!.Properties);

        Assert.True(fn.Parameters.Properties!.ContainsKey("include_metadata"));
        Assert.True(fn.Parameters.Properties.ContainsKey("anchor_doc_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("anchor_chunk_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("neighbor_window"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_doc_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_chunk_id"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_source_file"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_section_path"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_page_start"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_page_end"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_chunk_index_min"));
        Assert.True(fn.Parameters.Properties.ContainsKey("filter_chunk_index_max"));
        Assert.False(fn.Parameters.Properties.ContainsKey("index_name"));
    }

    [Fact]
    public void BuildQueryFunction_RemainsGenericFallbackWithIndexName()
    {
        var fn = QueryTools.BuildQueryFunction();

        Assert.Equal("execute_query", fn.Name);
        Assert.NotNull(fn.Parameters);
        Assert.NotNull(fn.Parameters!.Properties);
        Assert.True(fn.Parameters.Properties!.ContainsKey("index_name"));
    }
}

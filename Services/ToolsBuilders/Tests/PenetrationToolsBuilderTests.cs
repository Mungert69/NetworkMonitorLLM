using System.Linq;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class PenetrationToolsBuilderTests
{
    [Fact]
    public void BuildRunMetasploitFunction_UsesStructuredOptionsAndRequiredRouting()
    {
        var function = PenetrationTools.BuildRunMetasploitFunction();

        Assert.Equal("run_metasploit", function.Name);
        Assert.NotNull(function.Parameters?.Properties);
        Assert.Equal("object", function.Parameters!.Properties!["module_options"].Type);
        Assert.Contains("module_name", function.Parameters.Required!);
        Assert.Contains("target", function.Parameters.Required!);
        Assert.Contains("agent_location", function.Parameters.Required!);
    }

    [Fact]
    public void Builder_ExposesExpectedPenetrationTools()
    {
        var builder = new PenetrationExpertToolsBuilder();

        Assert.Equal(
            new[]
            {
                "run_metasploit",
                "search_metasploit_modules",
                "get_metasploit_module_info",
                "run_nmap",
                "execute_query_penetration"
            },
            builder.Tools.Select(tool => tool.Function!.Name));
    }

    [Fact]
    public void Prompt_ExamplesIncludeRequiredRoutingAndValidSearchJson()
    {
        var prompt = Assert.Single(new PenetrationExpertToolsBuilder()
            .GetSystemPrompt("2026-08-03T00:00:00Z", new LLMServiceObj(), "TestLLM")).Content;

        Assert.Contains("\"agent_location\": \"[AGENT_LOCATION]\"", prompt);
        Assert.Contains("\"keywords\": \"[KEYWORDS_TO_SEARCH_FOR]\",", prompt);
        Assert.DoesNotContain("\"THREADS\": 1,\n        },", prompt);
        Assert.Contains("\"module_name\": \"[FULL_MODULE_PATH]\",\n    \"agent_location\"", prompt);
        Assert.Contains("smallest port/service enumeration", prompt);
        Assert.DoesNotContain("Always begin with comprehensive port/service scanning", prompt);
    }
}

using NetworkMonitor.LLM.Services;
using Xunit;

namespace NetworkMonitorLLM.Tests.Prompts;

public class PromptRendererTests
{
    [Fact]
    public void BuildToolCallText_NamedBuilder_UsesNamedTokens()
    {
        var config = new LLMConfig
        {
            FunctionBuilder = "<minimax:tool_call><invoke name=\"{{function_name}}\">{{invoke_parameters}}</invoke></minimax:tool_call>"
        };

        string rendered = PromptRenderer.BuildToolCallText(config, "run_nmap", "{\"target\":\"127.0.0.1\"}");

        Assert.Contains("<invoke name=\"run_nmap\">", rendered);
        Assert.Contains("<parameter name=\"target\">", rendered);
        Assert.DoesNotContain("{{function_name}}", rendered);
        Assert.DoesNotContain("{{invoke_parameters}}", rendered);
    }

    [Fact]
    public void BuildToolCallText_UsesToolCallJsonNamedToken()
    {
        var config = new LLMConfig
        {
            FunctionBuilder = "<tool_call>{{tool_call_json}}</tool_call>"
        };

        string rendered = PromptRenderer.BuildToolCallText(config, "run_nmap", "{\"target\":\"127.0.0.1\"}");

        Assert.Contains("\"name\": \"run_nmap\"", rendered);
        Assert.Contains("\"arguments\": {\"target\":\"127.0.0.1\"}", rendered);
    }

    [Fact]
    public void BuildToolCallText_BuilderWithoutNamedTokens_FallsBackToFullJson()
    {
        var config = new LLMConfig
        {
            FunctionBuilder = "<tool_call>"
        };

        string rendered = PromptRenderer.BuildToolCallText(config, "run_nmap", "{\"target\":\"127.0.0.1\"}");

        Assert.Contains("\"name\": \"run_nmap\"", rendered);
        Assert.Contains("\"arguments\": {\"target\":\"127.0.0.1\"}", rendered);
    }
}

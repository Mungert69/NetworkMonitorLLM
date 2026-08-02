using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class MonitorSimpleToolsBuilderTests
{
    [Fact]
    public void GetSystemPrompt_IncludesSessionSpecificAgentContext()
    {
        var builder = new MonitorSimpleToolsBuilder();
        var firstSession = new LLMServiceObj
        {
            ChatAgentLocation = "Scanner - EU",
            ChatDeviceContext = "location=London; device=agent-one"
        };
        var secondSession = new LLMServiceObj
        {
            ChatAgentLocation = "Scanner - US",
            ChatDeviceContext = "location=New York; device=agent-two"
        };

        var firstPrompt = builder.GetSystemPrompt("2026-08-02T00:00:00", firstSession, "TestLLM");
        var secondPrompt = builder.GetSystemPrompt("2026-08-02T00:00:00", secondSession, "TestLLM");

        Assert.Single(firstPrompt);
        Assert.Single(secondPrompt);
        Assert.NotEqual(firstPrompt[0].Content, secondPrompt[0].Content);
        Assert.Contains("location=London", firstPrompt[0].Content);
        Assert.Contains("agent-one", firstPrompt[0].Content);
    }
}

public class SystemPromptWriterTests
{
    [Fact]
    public void CreateCachePromptServiceObj_ExcludesOnlySessionSpecificAgentContext()
    {
        var session = new LLMServiceObj
        {
            ChatAgentLocation = "Scanner - EU",
            ChatDeviceContext = "location=London; device=agent-one",
            ToolsDefinitionId = "monitor",
            LLMRunnerType = "TestLLM"
        };

        var cacheSession = SystemPromptWriter.CreateCachePromptServiceObj(session);

        Assert.NotSame(session, cacheSession);
        Assert.Empty(cacheSession.ChatAgentLocation);
        Assert.Empty(cacheSession.ChatDeviceContext);
        Assert.Equal(session.ToolsDefinitionId, cacheSession.ToolsDefinitionId);
        Assert.Equal(session.LLMRunnerType, cacheSession.LLMRunnerType);
    }
}

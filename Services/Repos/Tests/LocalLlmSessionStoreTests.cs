using System;
using System.IO;
using System.Threading.Tasks;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LocalLlmSessionStoreTests
{
    [Fact]
    public async Task SaveAndLoad_RoundTripsUiHistoryAndLocalContext()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), $"local-llm-session-{Guid.NewGuid():N}");
        try
        {
            var store = new LocalLlmSessionStore(rootPath);
            var savedSession = new HistoryDisplayName
            {
                SessionId = "session_user_1",
                LlmType = "TestLLM",
                History = new() { ChatMessage.FromUser("hello") },
                LocalLlmContext = "<|user|>hello<|assistant|>hi"
            };

            await store.SaveAsync(savedSession);
            var loadedSession = await store.LoadAsync(savedSession.SessionId);

            Assert.NotNull(loadedSession);
            Assert.Equal(savedSession.History[0].Content, loadedSession!.History[0].Content);
            Assert.Equal(savedSession.LocalLlmContext, loadedSession.LocalLlmContext);
        }
        finally
        {
            if (Directory.Exists(rootPath)) Directory.Delete(rootPath, recursive: true);
        }
    }
}

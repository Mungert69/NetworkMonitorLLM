using Newtonsoft.Json;
using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services
{
    public class HistoryDisplayName
    {
        [JsonProperty("name")]
        public string Name { get; set; } = "";

        [JsonProperty("sessionId")]
        public string SessionId { get; set; } = "";

        [JsonProperty("history")]
        public List<ChatMessage> History { get; set; } = new();

        // Position-aligned, immutable sequence values for History. They let the
        // memory index retain a message identity when the active history is trimmed.
        [JsonProperty("historySequences")]
        public List<long> HistorySequences { get; set; } = new();

        [JsonProperty("nextHistorySequence")]
        public long NextHistorySequence { get; set; }

        // Exact local llama.cpp context after the shared GGUF prompt cache.
        // This is separate from History, which is used to replay the UI transcript.
        [JsonProperty("localLlmContext")]
        public string LocalLlmContext { get; set; } = string.Empty;

        [JsonProperty("startUnixTime")]
        public long StartUnixTime { get; set; }

        [JsonProperty("userId")]
        public string UserId { get; set; } = "";
         [JsonProperty("llmType")]
         public string LlmType{ get; set; } = "";
    }

}

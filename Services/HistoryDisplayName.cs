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

        [JsonProperty("startUnixTime")]
        public long StartUnixTime { get; set; }

        [JsonProperty("userId")]
        public string UserId { get; set; } = "";
         [JsonProperty("llmType")]
         public string LlmType{ get; set; } = "";
    }

}

using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
namespace NetworkMonitor.LLM.Services;
public class HistoryDisplayName
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("sessionId")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("history")]
    public List<ChatMessage> History = new();

    [JsonPropertyName("startUnixTime")]
    public long StartUnixTime;

  [JsonPropertyName("userId")]
    public string UserId {get;set;} ="";

}

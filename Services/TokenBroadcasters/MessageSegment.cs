namespace NetworkMonitor.LLM.Services.Objects;
public class MessageSegment
{
    public string From { get; set; } = ""; // "user", "assistant", or "function"
    public string Recipient { get; set; } = "";// "llm", "user", or "function"
    public string Content { get; set; } = "";
}

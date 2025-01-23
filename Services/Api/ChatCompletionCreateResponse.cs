using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
namespace NetworkMonitor.LLM.Services;

public class ChatCompletionCreateResponseSuccess
{
    public bool Success { get; set; }
    public ChatCompletionCreateResponse Response { get; set; }
}


using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils;

namespace NetworkMonitor.LLM.Services;
public interface ILLMApi
{
    Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens);
    List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj);
    string WrapFunctionResponse(string name, string funcStr);
}

public static class LLMApiFactory
{
    /*public static ILLMApi CreateApi(string llmProvider, OpenAIService openAiService = null, string hfApiUrl = null, string hfAuthToken = null)
    {
        return llmProvider switch
        {
            "OpenAI" => new OpenAIApi(openAiService),
            "HuggingFace" => new HuggingFaceApi(hfApiUrl, hfAuthToken),
            _ => throw new ArgumentException($"Unknown LLM provider: {llmProvider}")
        };
    }*/
}

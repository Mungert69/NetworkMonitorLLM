using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Factory;
using NetworkMonitor.Utils;
using NetworkMonitor.LLM.Services;


namespace NetworkMonitor.LLM.Services;

public class ChatCompletionCreateResponseSuccess{
    public bool Success{get;set;}
    public ChatCompletionCreateResponse Response {get;set;}
}
public class HuggingFaceApi : ILLMApi
{
    ILogger _logger;
    private readonly HttpClient _httpClient;
    private readonly string _apiUrl;
    private readonly string _authToken;
    private readonly string _model;
    private readonly string _modelID;

    public HuggingFaceApi(ILogger logger,string apiUrl, string authToken, string modelID, string model)
    {
        _logger = logger;
        _httpClient = new HttpClient();
        _model=model;
        _modelID=modelID;
        _authToken=authToken;
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authToken);
        _apiUrl = $"{apiUrl.TrimEnd('/')}/models/{modelID}";

    _logger.LogInformation($"Initialized Hugging Face API with URL: {_apiUrl}");
    }

      public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj){
        return new List<ChatMessage>();
    }

    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages,  int maxTokens)
    {
        // Convert messages to Hugging Face prompt format
        var config = LLMConfigFactory.GetConfig(_model);
        var prompt = HuggingFaceChatConverter.ConvertChatMessagesToPrompt(messages, config);

        var response = await _httpClient.PostAsync(_apiUrl, new StringContent(JsonSerializer.Serialize(new
        {
            inputs = prompt,
            parameters = new { max_length = maxTokens }
        }), Encoding.UTF8, "application/json"));

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        var output = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(content);

        // Parse Hugging Face output into ChatCompletionCreateResponse format
        var chatResponse = new ChatCompletionCreateResponse
        {
             Choices = output.Select(o => new ChatChoiceResponse
            {
                Message = ChatMessage.FromAssistant(o["generated_text"])
            }).ToList()
        };

        return new ChatCompletionCreateResponseSuccess(){Success=true, Response=chatResponse};
    }
}

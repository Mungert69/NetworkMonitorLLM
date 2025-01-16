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

public class OpenAIApi : ILLMApi
{
    private readonly OpenAIService _openAiService;
     private IToolsBuilder _toolsBuilder;
     private string _gptModel = "gpt-4o-mini";


    public OpenAIApi(OpenAIService openAiService, IToolsBuilder toolsBuilder, string gptModel)
    {
        _gptModel= gptModel;
        _openAiService = openAiService;
        _toolsBuilder = toolsBuilder;
    }

    public string WrapFunctionResponse(string name, string funcStr){
        // Do nothing just return
        return funcStr;
 
    }
    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj){
        return _toolsBuilder.GetSystemPrompt(currentTime, serviceObj);
            
    }

    public async Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens)
    {
        var chatResponse= await _openAiService.ChatCompletion.CreateCompletion(new ChatCompletionCreateRequest
        {
            Messages = messages,
            MaxTokens = maxTokens,
            Model = _gptModel,
            Tools = _toolsBuilder.Tools,
            ToolChoice = _toolsBuilder.Tools != null ? ToolChoice.Auto : ToolChoice.None
        });
        return new ChatCompletionCreateResponseSuccess(){Success=chatResponse.Successful, Response=chatResponse};
    }
}

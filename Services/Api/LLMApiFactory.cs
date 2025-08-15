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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NetworkMonitor.LLM.Api;



namespace NetworkMonitor.LLM.Services;
public interface ILLMApi
{
    Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens, LLMServiceObj serviceObj);
    List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink=false);
    string GetFunctionNamesAsString(string separator = ", ");
     List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj);
      int SystemPromptCount { get ; }
      LLMConfig Config { get; }
    string WrapFunctionResponse(string name, string funcStr);
    
}



namespace NetworkMonitor.LLM.Services
{
    public static class LLMApiFactory
    {
        public static ILLMApi CreateApi(
            IConfiguration cfg,
            ILogger logger,
            MLParams mlParams,
            IToolsBuilder toolsBuilder,
            string serviceID,
            ILLMResponseProcessor responseProcessor,
            OpenAIService openAiService // you already pass this today for OpenAI HTTP
        )
        {
            var provider = cfg["LLM:Provider"] ?? "OpenAI";

            if (string.Equals(provider, "OpenAI", StringComparison.OrdinalIgnoreCase))
            {
                // your existing HTTP (what you showed)
                return new OpenAIApi(logger, mlParams, toolsBuilder, serviceID, responseProcessor, openAiService);
            }

            if (string.Equals(provider, "HuggingFace", StringComparison.OrdinalIgnoreCase))
            {
                var hfApiUrl = cfg["LLM:HuggingFace:BaseUrl"];
                var hfToken  = cfg["LLM:HuggingFace:ApiKey"];
                return new HuggingFaceApi(hfApiUrl, hfToken);
            }

            if (string.Equals(provider, "OpenAIRabbit", StringComparison.OrdinalIgnoreCase))
            {
                var amqpUrl     = cfg["LLM:Rabbit:AmqpUrl"] ?? "";
                var routingKey  = cfg["LLM:Rabbit:RoutingKey"] ?? "";
                var source      = cfg["LLM:Rabbit:ServiceSource"] ?? "openai.mq.client";

                var rabbit = new OpenAIApiRabbit(amqpUrl, routingKey, source);
                return new OpenAIApiRabbitApi(logger, mlParams, toolsBuilder, serviceID, responseProcessor, rabbit);
            }

            throw new ArgumentException($"Unknown LLM provider: {provider}");
        }
    }
}



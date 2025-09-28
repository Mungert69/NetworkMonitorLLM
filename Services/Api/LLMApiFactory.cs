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
using NetworkMonitor.Objects.Repository;
using Microsoft.Extensions.Configuration;


namespace NetworkMonitor.LLM.Services;

public interface ILLMApi
{
    Task<ChatCompletionCreateResponseSuccess> CreateCompletionAsync(List<ChatMessage> messages, int maxTokens, LLMServiceObj serviceObj);
    List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, bool noThink = false);
    string GetFunctionNamesAsString(string separator = ", ");
    List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj);
    int SystemPromptCount { get; }
    LLMConfig Config { get; }
    string WrapFunctionResponse(string name, string funcStr);

}


public class LLMApiFactory
{
    public  ILLMApi CreateApi(
 ILogger logger,
 MLParams mlParams,
 IToolsBuilder toolsBuilder,
 string serviceID,
 ILLMResponseProcessor responseProcessor,
SystemParams systemParams,
string provider,
 OpenAIService openAiService // you already pass this today for OpenAI HTTP
)
    {
        
        if (string.Equals(provider, "OpenAI", StringComparison.OrdinalIgnoreCase))
        {
            // your existing HTTP (what you showed)
            return new OpenAIApi(logger, mlParams, toolsBuilder, serviceID, responseProcessor, openAiService);
        }

        if (string.Equals(provider, "HuggingFace", StringComparison.OrdinalIgnoreCase))
        {

            return new HuggingFaceApi(logger, mlParams, toolsBuilder, serviceID, responseProcessor, false);
        }

        if (string.Equals(provider, "OpenAIRabbit", StringComparison.OrdinalIgnoreCase))
        {

            var rabbit = new RabbitTransport(responseProcessor.RabbitRepo, systemParams.ThisSystemUrl, systemParams.RabbitRoutingKey, logger);
            return new OpenAIRabbitApi(logger, mlParams, toolsBuilder, serviceID, responseProcessor, rabbit);
        }
         if (string.Equals(provider, "HuggingFaceRabbit", StringComparison.OrdinalIgnoreCase))
        {

            var rabbit = new RabbitTransport(responseProcessor.RabbitRepo, systemParams.ThisSystemUrl, systemParams.RabbitRoutingKey, logger);
            return new HuggingFaceRabbitApi(logger, mlParams, toolsBuilder, serviceID, responseProcessor, rabbit);
        }

        throw new ArgumentException($"Unknown LLM provider: {provider}");
    }
}




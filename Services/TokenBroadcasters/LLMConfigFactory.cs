using System;
using Microsoft.Extensions.Logging;
using NetworkMonitor.LLM.Services;
using System.Collections.Generic;
namespace NetworkMonitor.LLM.Services;
public static class LLMConfigFactory
{
    private static readonly Dictionary<string, LLMConfig> _llmConfigs = new()
    {
        ["func_2.4"] = new LLMConfig
        {
            UserInputTemplate = "<|from|> user\\\n<|recipient|> all\\\n<|content|>{0}",
            AssistantMessageTemplate = "<|from|> assistant\\\n<|recipient|> all\\\n<|content|>{0}\\\n",
            EOFToken = "<|eot_id|>",
            FunctionResponseTemplate = "<|from|> {0}\\\n<|recipient|> all\\\n<|content|>{1}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_2_4(responseProcessor, logger, xmlFunctionParsing)

        },
        ["func_2.5"] = new LLMConfig
        {
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOFToken = "<|eot_id|>",
            FunctionResponseTemplate = "<|start_header_id|>tool<|end_header_id|>\\\n\\\nname={0} {1}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_2_5(responseProcessor, logger, xmlFunctionParsing)

        },
        // Configuration for func_3.1
        ["func_3.1"] = new LLMConfig
        {
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOFToken = "<|eot_id|>",
            FunctionResponseTemplate = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n{1}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_3_1(responseProcessor, logger, xmlFunctionParsing)

        },

        // Configuration for func_3.2
        ["func_3.2"] = new LLMConfig
        {
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOFToken = "<|eot_id|>",
            FunctionResponseTemplate = "<|start_header_id|>tool<|end_header_id|>\\\n\\\n{1}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_3_2(responseProcessor, logger, xmlFunctionParsing)

        },
        ["llama_3.2"] = new LLMConfig
        {
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOFToken = "<|eot_id|>",
            FunctionResponseTemplate = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n{1}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                  new TokenBroadcasterLlama_3_2(responseProcessor, logger, xmlFunctionParsing)
        },


        // Configuration for phi_4
        ["phi_4"] = new LLMConfig
        {

            UserInputTemplate = "<|im_start|>user<|im_sep|>\\\n{0}",
            AssistantMessageTemplate = "<|im_start|>assistant<|im_sep|>\\\n{0}<|im_end|>",
            EOFToken = "<|im_end|>",
            FunctionResponseTemplate = "<|im_start|>user<|im_sep|>\\\n<tool_response>\\\n{1}\\\n</tool_response>",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                new TokenBroadcasterPhi_4(responseProcessor, logger, xmlFunctionParsing)
        },

        // Configuration for qwen_2.5
        ["qwen_2.5"] = new LLMConfig
        {
            UserInputTemplate = "<|im_start|>user\\\n{0}",
            AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",
            EOFToken = "<|im_end|>",
            FunctionResponseTemplate = "<|im_start|>assistant\\\n<tool_response>\\\n{1}\\\n</tool_response>",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                    new TokenBroadcasterQwen_2_5(responseProcessor, logger, xmlFunctionParsing)
        },

        // Configuration for standard
        ["standard"] = new LLMConfig
        {
            UserInputTemplate = "Function Call : {0}",
            AssistantMessageTemplate = "Response : {0}",
            EOFToken = "",
            FunctionResponseTemplate = "FUNCTION RESPONSE: {1}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                    new TokenBroadcasterStandard(responseProcessor, logger, xmlFunctionParsing)
        }
    };

    public static LLMConfig GetConfig(string llmVersion)
    {
        if (_llmConfigs.TryGetValue(llmVersion, out var config))
        {
            return config;
        }

        throw new KeyNotFoundException($"LLM version '{llmVersion}' is not configured.");
    }
}
public class LLMConfig
{
    public string UserInputTemplate { get; set; } = string.Empty;
    public string AssistantMessageTemplate { get; set; } = string.Empty;
    public string EOFToken { get; set; } = string.Empty;
    public string FunctionResponseTemplate { get; set; } = string.Empty;
    public string ReversePrompt { get; set; } = string.Empty;
    public string ExtraReversePrompt { get; set; } = string.Empty;
    public Func<ILLMResponseProcessor, ILogger, bool, ITokenBroadcaster> CreateBroadcaster { get; set; } =
            (_, _, _) => throw new InvalidOperationException("No broadcaster defined for this LLMConfig.");

}


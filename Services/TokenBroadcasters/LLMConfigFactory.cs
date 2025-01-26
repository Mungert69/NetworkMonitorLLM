using System;
using Microsoft.Extensions.Logging;
using NetworkMonitor.LLM.Services;
using System.Collections.Generic;
namespace NetworkMonitor.LLM.Services;
public static class LLMConfigFactory
{
    private static readonly string _xmlPromptFooter=@"Each function call should be represented as an XML document with a root element <function_call> and a <parameters> element nested inside it.

Function Call Format Requirements:

    When you decide to call a function, do not return JSON. Instead, return XML following this format:

<function_call name=""{function_name}"">
    <parameters>
        <!-- Each parameter as an XML element -->
        <parameter_name>parameter_value</parameter_name>
        ...
    </parameters>
</function_call>

Where:

    {function_name} is replaced with the actual function name you want to call.
    Each parameter from the function definition becomes an XML element inside <parameters>.
    Treat all parameter values as strings for simplicity, placing them inside the XML elements.
";
    private static readonly Dictionary<string, LLMConfig> _llmConfigs = new()
    {
        ["func_2.4"] = new LLMConfig
        {
            UserReplace = "<|from|> user\\\n<|recipient|> all\\\n<|content|>",
            FunctionReplace = "",
            AssistantHeader = "<|from|> assistant\\\n<|recipient|> all\\\n<|content|>",
            UserInputTemplate = "<|from|> user\\\n<|recipient|> all\\\n<|content|>{0}",
            AssistantMessageTemplate = "<|from|> assistant\\\n<|recipient|> all\\\n<|content|>{0}\\\n",
            EOTToken = "<|stop|>",
            FunctionResponseTemplate = "<|from|> {0}\\\n<|recipient|> all\\\n<|content|>{1}",
            FunctionResponse = "<|from|> {0}\n<|recipient|> all\n<|content|>{1}",
            FunctionDefsWrap = "{0}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_2_4(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

        },
        ["func_2.5"] = new LLMConfig
        {
            UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
            FunctionReplace = "<|start_header_id|>tool<|end_header_id|>\\\n\\\n",
            AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOTToken = "<|eot_id|>",
            FunctionResponseTemplate = "<|start_header_id|>tool<|end_header_id|>\\\n\\\nname={0} {1}",
            FunctionResponse = "<|reserved_special_token_249|>{0}\n{1}",
            FunctionDefsWrap = "{0}",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_2_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

        },
        // Configuration for func_3.1
        ["func_3.1"] = new LLMConfig
        {
            UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
            FunctionReplace = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n",
            AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOTToken = "<|eot_id|>",
            EOMToken = "<|eom_id|>",
            FunctionResponseTemplate = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n{1}",
            FunctionResponse = "<function_response name={0}>{1}</function_response>",
            FunctionDefsWrap = "{0}",
            PromptFooter = @"
Think very carefully before calling functions.
If you choose to call a function, ONLY reply in the following format:
<function={function_name}>{parameters}</function>
where
parameters => a JSON dict with the function argument name as key and function argument value as value.


Here is an example:
<function=example_function_name>{""example_name"": ""example_value""}</function>

Reminder:
- Function calls MUST follow the specified format, start with <function= and end with </function>
- Required parameters MUST be specified
- Only call one function at a time
- Put the entire function call reply on one line
",

            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_3_1(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
        },

        // Configuration for func_3.2
        ["func_3.2"] = new LLMConfig
        {
            UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
            FunctionReplace = "<|start_header_id|>tool<|end_header_id|>\\\n\\\n",
            AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOTToken = "<|eot_id|>",
            FunctionResponseTemplate = "<|start_header_id|>tool<|end_header_id|>\\\n\\\n{1}",
            FunctionResponse = "<function_response name={0}>{1}</function_response>",
            FunctionDefsWrap = "{0}",
            PromptFooter=@"Only execute function(s) when absolutely necessary.
Ask for the required input to:recipient==all
Use JSON for function arguments.
Respond in this format:
>>>${recipient}
${content}
",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                   new TokenBroadcasterFunc_3_2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

        },
        ["llama_3.2"] = new LLMConfig
        {
            UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
            FunctionReplace = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n",
            AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
            UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            EOTToken = "<|eot_id|>",
            EOMToken = "<|eom_id|>",
            FunctionResponseTemplate = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n{1}",
            FunctionResponse = "{1}",
            FunctionDefsWrap = @"
Ensure that any function calls you use align with the user's request. Use only the functions necessary for the task. For failed function calls, provide feedback about the issue before retrying or switching functions.

Here is a list of functions in JSON format that you can invoke:

{0}",
            XmlPromptFooter=_xmlPromptFooter,
            PromptFooter = @"Think very carefully before calling functions.

 If you choose to call a function, ONLY reply in the following format:

 {""name"": ""function_name"", ""parameters"": {parameters}}

 Where:

     function_name: The name of the function being called.
     parameters: A JSON object where the argument names (keys) are taken from the function definition, and the argument values (values) must be in the correct data types (such as strings, numbers, booleans, etc.) as specified in the function's definition.
 
 Notes:
    The format of the function call is json. Only valid json should be used. For example
    Numbers remain numbers (e.g., 123, 59.5)
    Booleans are true or false without quotes around them
    Strings are enclosed in quotes (e.g., ""escaped json string""). The string must be a valid json string.
    Refer to the function definitions to ensure all parameters of the correct types

Important: You will call functions only when necessary. Checking with the user before calling more functions. You will only provide json in your responses when you intend to call a function.
VERY IMPORTANT : Only call functions using this format :  {""name"": ""function_name"", ""parameters"": {parameters}}
",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                  new TokenBroadcasterLlama_3_2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
        },


        // Configuration for phi_4
        ["phi_4"] = new LLMConfig
        {
            UserReplace = "<|im_start|>user<|im_sep|>\\\n",
            FunctionReplace = "<|im_start|>user<|im_sep|>\\\n<function_response>\\\n",
            AssistantHeader = "<|im_start|>assistant<|im_sep|>\n",
            UserInputTemplate = "<|im_start|>user<|im_sep|>\\\n{0}",
            AssistantMessageTemplate = "<|im_start|>assistant<|im_sep|>\\\n{0}<|im_end|>",
            EOTToken = "<|im_end|>",
            FunctionResponseTemplate = "<|im_start|>user<|im_sep|>\\\n<function_response name={0}>\\\n{1}\\\n</function_response>",
            FunctionResponse = "<function_response name={0}>{1}</function_response>",
            FunctionDefsWrap = @"
You have access to the following functions:

{0}",
            XmlPromptFooter=_xmlPromptFooter,
            PromptFooter = @"
Think very carefully before calling functions.
If you choose to call a function, ONLY reply in the following format:
<function={function_name}>{parameters}</function>
where
parameters => a JSON dict with the function argument name as key and function argument value as value.


Here is an example:
<function=example_function_name>{""example_name"": ""example_value""}</function>

Reminder:
- Function calls MUST follow the specified format, start with <function= and end with </function>
- Required parameters MUST be specified
- Only call one function at a time
- Put the entire function call reply on one line
",

            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                new TokenBroadcasterPhi_4(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
        },

        // Configuration for qwen_2.5
        ["qwen_2.5"] = new LLMConfig
        {
            UserReplace = "<|im_start|>user\\\n",
            FunctionReplace = "<|im_start|>assistant\\\n<tool_response>",
            AssistantHeader = "<|im_start|>assistant\n",
            UserInputTemplate = "<|im_start|>user\\\n{0}",
            AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",
            EOTToken = "<|im_end|>",
            FunctionResponseTemplate = "<|im_start|>assistant\\\n<tool_response>\\\n{1}\\\n</tool_response>",
            FunctionResponse = "<tool_response>{1}</tool_response>",
            FunctionDefsWrap = @"# Tools

You may call one or more functions to assist with the user query.

You are provided with function signatures within <tools></tools> XML tags:
<tools>
{0}
</tools>",
            XmlPromptFooter=_xmlPromptFooter,
            PromptFooter=@"For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:
<tool_call>
{""name"": <function-name>, ""arguments"": <args-json-object>}
</tool_call>
Reminder:
- Function calls MUST follow the specified format : <tool_call> {""name"": <function-name>, ""arguments"": <args-json-object>} </tool_call>
- The function call repsonses are between tags <tool_response> and </tool_response> 
- Required parameters MUST be specified
- Only call one function at a time
- Important: You will call functions only when necessary. Checking with the user before calling more functions.
",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                    new TokenBroadcasterQwen_2_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
        },

        // Configuration for qwen_2.5
        ["gemma_2"] = new LLMConfig
        {
            UserReplace = "<start_of_turn>user\\\n",
            FunctionReplace = "<start_of_turn>user\\\nFunction response:",
            AssistantHeader = "<start_of_turn>model\n",
            UserInputTemplate = "<start_of_turn>user\\\n{0}",
            AssistantMessageTemplate = "<start_of_turn>model\\\n{0}<end_of_turn>",
            EOTToken = "<end_of_turn>",
            FunctionResponseTemplate = "<start_of_turn>user\\\nFunction response: {1}",
            FunctionResponse = "Function response: {1}",
            FunctionDefsWrap = "{0}",
            PromptFooter="",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                    new TokenBroadcasterQwen_2_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
        },

        // Configuration for standard
        ["standard"] = new LLMConfig
        {
            UserReplace = "",
            FunctionReplace = "Function Call :",
            AssistantHeader = "",
            UserInputTemplate = "Function Call : {0}",
            AssistantMessageTemplate = "Response : {0}",
            EOTToken = "",
            FunctionResponseTemplate = "FUNCTION RESPONSE: {1}",
            FunctionResponse = "FUNCTION RESPONSE: {1}",
            FunctionDefsWrap = "{0}",
            PromptFooter="",
            CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                    new TokenBroadcasterStandard(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
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

   private static readonly Lazy<HashSet<string>> _ignoreParameters = new(() => 
    new HashSet<string> { "source_code" });

public static HashSet<string> IgnoreParameters => _ignoreParameters.Value;
}
public class LLMConfig
{
    public string UserReplace { get; set; } = string.Empty;
    public string FunctionReplace { get; set; } = string.Empty;
    public string AssistantHeader { get; set; } = string.Empty;
    public string UserInputTemplate { get; set; } = string.Empty;
    public string AssistantMessageTemplate { get; set; } = string.Empty;
    public string EOTToken { get; set; } = string.Empty;
    public string EOMToken { get; set; } = string.Empty;
    public string FunctionResponseTemplate { get; set; } = string.Empty;
     public string FunctionResponse { get; set; } = string.Empty;
     public string FunctionDefsWrap { get; set; } = string.Empty;
      public string PromptFooter { get; set; } = string.Empty;
         public string XmlPromptFooter { get; set; } = string.Empty;
       
    public string ReversePrompt { get; set; } = string.Empty;
    public string ExtraReversePrompt { get; set; } = string.Empty;
    public Func<ILLMResponseProcessor, ILogger, bool, ITokenBroadcaster> CreateBroadcaster { get; set; } =
            (_, _, _) => throw new InvalidOperationException("No broadcaster defined for this LLMConfig.");

}


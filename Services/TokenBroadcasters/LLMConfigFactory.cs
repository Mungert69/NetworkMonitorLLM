using System;
using Microsoft.Extensions.Logging;
using NetworkMonitor.LLM.Services;
using System.Collections.Generic;
namespace NetworkMonitor.LLM.Services;

public static class LLMConfigFactory
{
    private static readonly string _xmlPromptFooter = @"Each function call should be represented as an XML document with a root element <function_call> and a <parameters> element nested inside it.

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
    private static readonly string _miniCpmPromptFooter = @"If you choose to call a function, ONLY reply in the following format with NO suffix:

<function name=""function-name"">
<param name=""param-name"">param-value</param>
</function>

Reminder:
- Function calls MUST follow the specified format
- Required parameters MUST be specified
- You may provide optional reasoning for your function call in natural language BEFORE the function call, but NOT after
- If a parameter value contains <, & or newline characters, wrap it in a CDATA block:
  <param name=""param-name""><![CDATA[...multi-line value...]]></param>
- If there is no function call available, answer the question like normal with your current knowledge and do not tell the user about function calls
";
    public static LLMConfig GetConfig(string llmVersion)
    {
        return llmVersion switch
        {
            "func_2.4" => new LLMConfig
            {
                UserReplace = "<|from|> user\\\n<|recipient|> all\\\n<|content|>",
                FunctionReplace = "",
                AssistantHeader = "<|from|> assistant\\\n<|recipient|> all\\\n<|content|>",
                UserInputTemplate = "<|from|> user\\\n<|recipient|> all\\\n<|content|>{0}",
                AssistantMessageTemplate = "<|from|> assistant\\\n<|recipient|> all\\\n<|content|>{0}\\\n",
                SystemMessageTemplate = "<|from|> system\\\n<|recipient|> all\\\n<|content|>{0}\\\n",
                EOTToken = "<|stop|>",
                FunctionResponseTemplate = "<|from|> {0}\\\n<|recipient|> all\\\n<|content|>{1}",
                FunctionBuilder = "<|from|> {{function_name}}\\\n<|recipient|> all\\\n<|content|>{{arguments_json}}",
                FunctionResponse = "<|from|> {0}\n<|recipient|> all\n<|content|>{1}",
                FunctionDefsWrap = "{0}",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                       new TokenBroadcasterFunc_2_4(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

            },
            "func_2.5" => new LLMConfig
            {
                UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
                FunctionReplace = "<|start_header_id|>tool<|end_header_id|>\\\n\\\n",
                AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
                UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
                AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                SystemMessageTemplate = "<|start_header_id|>system<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                EOTToken = "<|eot_id|>",
                FunctionResponseTemplate = "<|start_header_id|>tool<|end_header_id|>\\\n\\\nname={0} {1}",

                FunctionBuilder = " name = {{function_name}} {{arguments_json}}",
                FunctionResponse = "<|reserved_special_token_249|>{0}\n{1}",
                FunctionDefsWrap = "{0}",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                       new TokenBroadcasterFunc_2_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

            },
            "func_3.1" => new LLMConfig
            {
                UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
                FunctionReplace = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n",
                AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
                UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
                AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                SystemMessageTemplate = "<|start_header_id|>system<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                EOTToken = "<|eot_id|>",
                EOMToken = "<|eom_id|>",
                FunctionResponseTemplate = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n{1}",

                FunctionBuilder = "<function={{function_name}}>{{arguments_json}}</function>",
                FunctionResponse = "{1}",
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
            "func_3.2" => new LLMConfig
            {
                UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
                FunctionReplace = "<|start_header_id|>tool<|end_header_id|>\\\n\\\n",
                AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
                UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
                AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                SystemMessageTemplate = "<|start_header_id|>system<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                EOTToken = "<|eot_id|>",
                FunctionResponseTemplate = "<|start_header_id|>tool<|end_header_id|>\\\n\\\n{1}",

                FunctionResponse = "{1}",
                FunctionDefsWrap = "{0}",
                PromptFooter = @"Only execute function(s) when absolutely necessary.
Ask for the required input to:recipient==all
Use JSON for function arguments.
Respond in this format:
>>>${recipient}
${content}
",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                       new TokenBroadcasterFunc_3_2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

            },
            "llama_3.2" => new LLMConfig
            {
                UserReplace = "<|start_header_id|>user<|end_header_id|>\\\n\\\n",
                FunctionReplace = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n",
                AssistantHeader = "<|start_header_id|>assistant<|end_header_id|>\n\n",
                UserInputTemplate = "<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
                AssistantMessageTemplate = "<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                SystemMessageTemplate = "<|start_header_id|>system<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
                EOTToken = "<|eot_id|>",
                EOMToken = "<|eom_id|>",
                FunctionResponseTemplate = "<|start_header_id|>ipython<|end_header_id|>\\\n\\\n{1}",

                FunctionBuilder = "{\"name\":\"{{function_name}}\", \"parameters\":{{arguments_json}}}",
                FunctionResponse = "{1}",
                FunctionDefsWrap = @"
Ensure that any function calls you use align with the user's request. Use only the functions necessary for the task. For failed function calls, provide feedback about the issue before retrying or switching functions.

Here is a list of functions in JSON format that you can invoke:

{0}",
                XmlPromptFooter = _xmlPromptFooter,
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
            // Only working for OpenAIRunner at the moment. When trying to fix is the | suposed to be a special character with ' | ' the ascii for that?
            "deepseek_3.2_exp" => new LLMConfig
            {
                UserReplace = "<｜User｜>",
                FunctionReplace = "<｜tool▁output▁begin｜>",
                AssistantHeader = "<｜Assistant｜>",
                UserInputTemplate = "<｜User｜>{0}",
                AssistantMessageTemplate = "<｜Assistant｜>{0}<｜end▁of▁sentence｜>",
                SystemMessageTemplate = "{0}",
                EOTToken = "<｜end▁of▁sentence｜>",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionResponseTemplate = "<｜tool▁output▁begin｜>{1}<｜tool▁output▁end｜>",
                FunctionBuilder = "<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>{{function_name}}<｜tool▁sep｜>{{arguments_json}}<｜tool▁call▁end｜><｜tool▁calls▁end｜>",
                FunctionResponse = "{1}",
                FunctionDefsWrap = @"Available tools:
{0}",
                XmlPromptFooter = _xmlPromptFooter,
                PromptFooter = @"When calling a tool, respond ONLY with tool call blocks using this format:
<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>{function_name}<｜tool▁sep｜>{arguments_json}<｜tool▁call▁end｜><｜tool▁calls▁end｜>
Do not add any other text around the tool call.",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                      new TokenBroadcasterDeepseek_3_2_Exp(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "deepseek_r1" => new LLMConfig
            {
                UserReplace = "<｜User｜>",
                FunctionReplace = "<｜tool▁outputs▁begin｜>",
                AssistantHeader = "<｜Assistant｜>",
                UserInputTemplate = "<｜User｜>{0}",
                AssistantMessageTemplate = "<｜Assistant｜>{0}<｜end▁of▁sentence｜>",
                SystemMessageTemplate = "{0}",
                EOTToken = "<｜end▁of▁sentence｜>",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionResponseTemplate = "<｜tool▁output▁begin｜>{1}<｜tool▁output▁end｜>",
                FunctionBuilder = "<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>{{function_name}}\n```json\n{{arguments_json}}\n```<｜tool▁call▁end｜><｜tool▁calls▁end｜>",
                FunctionResponse = "{1}",
                FunctionDefsWrap = @"Available tools:
{0}",
                XmlPromptFooter = _xmlPromptFooter,
                PromptFooter = @"When calling a tool, respond ONLY with tool call blocks using this format:
<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>{function_name}
```json
{arguments_json}
```
<｜tool▁call▁end｜><｜tool▁calls▁end｜>
Do not add any other text around the tool call.",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                      new TokenBroadcasterDeepseekR1(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },


            // Configuration for phi_4
            "phi_4" => new LLMConfig
            {
                UserReplace = "<|im_start|>user<|im_sep|>\\\n",
                FunctionReplace = "<|im_start|>user<|im_sep|>\\\n<function_response>\\\n",
                AssistantHeader = "<|im_start|>assistant<|im_sep|>\n",
                UserInputTemplate = "<|im_start|>user<|im_sep|>\\\n{0}",
                AssistantMessageTemplate = "<|im_start|>assistant<|im_sep|>\\\n{0}<|im_end|>",
                SystemMessageTemplate = "<|im_start|>system<|im_sep|>\\\n{0}<|im_end|>",
                EOTToken = "<|im_end|>",
                FunctionResponseTemplate = "<|im_start|>user<|im_sep|>\\\n<function_response name={0}>\\\n{1}\\\n</function_response>",
                ThinkBeginToken = "<reasoning>",
                ThinkEndToken = "</reasoning>",
                FunctionBuilder = "<function={{function_name}}>{{arguments_json}}</function>",
                FunctionResponse = "{1}",
                FunctionDefsWrap = @"
You have access to the following functions:

{0}",
                XmlPromptFooter = _xmlPromptFooter,
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

            "phi_4_mini" => new LLMConfig
            {
                UserReplace = "<|user|>\\\n",
                FunctionReplace = "<|tool_response|>",
                AssistantHeader = "<|assistant|>\n",
                UserInputTemplate = "<|user|>\\\n{0}",
                AssistantMessageTemplate = "<|assistant|>\\\n{0}<|end|>",
                SystemMessageTemplate = "<|system|>\\\n{0}<|end|>",
                EOTToken = "<|end|>",
                FunctionResponseTemplate = "<|tool_response|>[{1}]",

                FunctionBuilder = "<tool_call>{{tool_call_json}}</tool_call>",
                FunctionResponse = "<|tool_response|>[{1}]",
                FunctionDefsWrap = @"
You are a helpful assistant with some tools.
<|tool|>
{0}
<|/tool|>",
                XmlPromptFooter = _xmlPromptFooter,
                PromptFooter = @"For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:
<tool_call>
{""name"": <function-name>, ""arguments"": <args-json-object>}
</tool_call>
Reminder:
- Function calls MUST follow the specified format : <tool_call> {""name"": <function-name>, ""arguments"": <args-json-object>} </tool_call>
- The function call repsonses after the tag <tool_response>
- Required parameters MUST be specified
- Only call one function at a time
- Important: You will call functions only when necessary. Checking with the user before calling more functions.
",

                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                    new TokenBroadcasterQwen_2_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },


            // Configuration for qwen_2.5
            "qwen_2.5" => new LLMConfig
            {
                UserReplace = "<|im_start|>user\\\n",
                FunctionReplace = "<|im_start|>user\\\n<tool_response>",
                AssistantHeader = "<|im_start|>assistant\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",
                EOTToken = "<|im_end|>",
                FunctionResponseTemplate = "<|im_start|>user\\\n<tool_response>\\\n{1}\\\n</tool_response>",
                FunctionBuilder = "<tool_call>\n{{tool_call_json}}\n</tool_call>",
                FunctionResponse = "<tool_response>{1}</tool_response>",
                FunctionDefsWrap = @"# Tools

You may call one or more functions to assist with the user query.

You are provided with function signatures within <tools></tools> XML tags:
<tools>
{0}
</tools>",
                XmlPromptFooter = _xmlPromptFooter,
                PromptFooter = @"For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:
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

            // mellum_2 follows the same chat/tool template as qwen_3.5
            "mellum_2" => new LLMConfig
            {
                UserReplace = "<|im_start|>user\\\n",
                FunctionReplace = "<|im_start|>user\\\n<tool_response>",
                AssistantHeader = "<|im_start|>assistant\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",
                EOTToken = "<|im_end|>",
                FunctionResponseTemplate = "<|im_start|>user\\\n<tool_response>\\\n{1}\\\n</tool_response>",
                NoThinkToken = "/no_think",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                // Note: {2} is the XML parameter block rendered by PromptRenderer (JSON args -> <parameter=...>...</parameter>).
                // Use this for models/templates that require XML tool calls with explicit <parameter> tags (e.g., Qwen 3.5).
                FunctionBuilder = "<tool_call>\n<function={{function_name}}>\n{{xml_parameters}}\n</function>\n</tool_call>",
                FunctionResponse = "<tool_response>\n{1}\n</tool_response>",
                FunctionDefsWrap = @"# Tools

You have access to the following functions:

<tools>
{0}
</tools>",
                XmlPromptFooter = _xmlPromptFooter,
                PromptFooter = @"If you choose to call a function ONLY reply in the following format with NO suffix:

<tool_call>
<function=example_function_name>
<parameter=example_parameter_1>
value_1
</parameter>
<parameter=example_parameter_2>
This is the value for the second parameter
that can span
multiple lines
</parameter>
</function>
</tool_call>

Reminder:
- Function calls MUST follow the specified format: an inner <function=...></function> block must be nested within <tool_call></tool_call> XML tags
- Required parameters MUST be specified
- You may provide optional reasoning for your function call in natural language BEFORE the function call, but NOT after
- If there is no function call available, answer the question like normal with your current knowledge and do not tell the user about function calls",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterMellum_2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "qwen_3" => new LLMConfig
            {
                UserReplace = "<|im_start|>user\\\n",
                FunctionReplace = "<|im_start|>user\\\n<tool_response>",
                AssistantHeader = "<|im_start|>assistant\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",
                EOTToken = "<|im_end|>",
                FunctionResponseTemplate = "<|im_start|>user\\\n<tool_response>\\\n{1}\\\n</tool_response>",
                NoThinkToken = "/no_think",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionBuilder = "<tool_call>\n{{tool_call_json}}\n</tool_call>",
                FunctionResponse = "<tool_response>\n{1}\n</tool_response>",
                FunctionDefsWrap = @"# Tools

You may call one or more functions to assist with the user query.

You are provided with function signatures within <tools></tools> XML tags:
<tools>
{0}
</tools>",
                XmlPromptFooter = _xmlPromptFooter,
                PromptFooter = @"For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:
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
                        new TokenBroadcasterQwen_3(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "qwen_3.5" or "qwen_3_5" => new LLMConfig
            {
                UserReplace = "<|im_start|>user\\\n",
                FunctionReplace = "<|im_start|>user\\\n<tool_response>",
                AssistantHeader = "<|im_start|>assistant\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",
                EOTToken = "<|im_end|>",
                FunctionResponseTemplate = "<|im_start|>user\\\n<tool_response>\\\n{1}\\\n</tool_response>",
                NoThinkToken = "/no_think",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                // Note: {2} is the XML parameter block rendered by PromptRenderer (JSON args -> <parameter=...>...</parameter>).
                // Use this for models/templates that require XML tool calls with explicit <parameter> tags (e.g., Qwen 3.5).
                FunctionBuilder = "<tool_call>\n<function={{function_name}}>\n{{xml_parameters}}\n</function>\n</tool_call>",
                FunctionResponse = "<tool_response>\n{1}\n</tool_response>",
                FunctionDefsWrap = @"# Tools

You have access to the following functions:

<tools>
{0}
</tools>",
                XmlPromptFooter = _xmlPromptFooter,
                PromptFooter = @"If you choose to call a function ONLY reply in the following format with NO suffix:

<tool_call>
<function=example_function_name>
<parameter=example_parameter_1>
value_1
</parameter>
<parameter=example_parameter_2>
This is the value for the second parameter
that can span
multiple lines
</parameter>
</function>
</tool_call>

Reminder:
- Function calls MUST follow the specified format: an inner <function=...></function> block must be nested within <tool_call></tool_call> XML tags
- Required parameters MUST be specified
- You may provide optional reasoning for your function call in natural language BEFORE the function call, but NOT after
- If there is no function call available, answer the question like normal with your current knowledge and do not tell the user about function calls",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterQwen_3_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "minicpm_5" or "minicpm-5" => new LLMConfig
            {
                UserReplace = "<|im_start|>user\\\n",
                FunctionReplace = "<|im_start|>user\\\n<tool_response>",
                AssistantHeader = "<|im_start|>assistant\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",
                EOTToken = "<|im_end|>",
                FunctionResponseTemplate = "<|im_start|>user\\\n<tool_response>\\\n{1}\\\n</tool_response>",
                NoThinkToken = "/no_think",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionBuilder = "<function name=\"{{function_name}}\">\n{{param_elements}}\n</function>",
                FunctionResponse = "<tool_response>\n{1}\n</tool_response>",
                FunctionDefsWrap = @"# Tools

You are provided with function signatures within <tools></tools> XML tags:
<tools>
{0}
</tools>",
                XmlPromptFooter = _miniCpmPromptFooter,
                PromptFooter = _miniCpmPromptFooter,
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterMiniCPM_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "minimax_2.5" or "minimax_2_5" => new LLMConfig
            {
                UserReplace = "]~b]user\\\n",
                FunctionReplace = "]~b]tool\\\n",
                AssistantHeader = "]~b]ai\\\n<think>\\\n",
                UserInputTemplate = "]~b]user\\\n{0}[e~[\\\n",
                AssistantMessageTemplate = "]~b]ai\\\n{0}[e~[\\\n",
                SystemMessageTemplate = "]~!b[]~b]system\\\n{0}[e~[\\\n",
                EOTToken = "[e~[",
                FunctionResponseTemplate = "]~b]tool\\\n<response>{1}</response>[e~[\\\n",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionBuilder = "<minimax:tool_call>\\\n<invoke name=\"{{function_name}}\">\\\n{{invoke_parameters}}\\\n</invoke>\\\n</minimax:tool_call>",
                FunctionResponse = "<response>{1}</response>",
                FunctionDefsWrap = @"# Tools
You may call one or more tools to assist with the user query.
Here are the tools available in JSONSchema format:
<tools>
{0}
</tools>",
                PromptFooter = @"When making tool calls, use XML format to invoke tools and pass parameters:
<minimax:tool_call>
<invoke name=""tool-name-1"">
<parameter name=""param-key-1"">param-value-1</parameter>
<parameter name=""param-key-2"">param-value-2</parameter>
...
</invoke>
</minimax:tool_call>",
                XmlPromptFooter = @"When making tool calls, use XML format to invoke tools and pass parameters:
<minimax:tool_call>
<invoke name=""tool-name-1"">
<parameter name=""param-key-1"">param-value-1</parameter>
<parameter name=""param-key-2"">param-value-2</parameter>
...
</invoke>
</minimax:tool_call>",
                AppendEotToSuffix = false,
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterMinimax_2_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "glm_4.5" or "glm_4_5" => new LLMConfig
            {
                UserReplace = "<|user|>",
                FunctionReplace = "<|observation|><tool_response>",
                AssistantHeader = "<|assistant|>\n",
                UserInputTemplate = "<|user|>{0}",
                AssistantMessageTemplate = "<|assistant|>\n{0}",
                SystemMessageTemplate = "<|system|>{0}",
                EOTToken = "<|user|>",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionResponseTemplate = "<|observation|><tool_response>{1}</tool_response>",
                BosToken = "[gMASK]<sop>\n",
                AppendEotToSuffix = false,
                FunctionBuilder = "<tool_call>{{function_name}}{{arg_key_values}}</tool_call>",
                FunctionResponse = "<tool_response>{1}</tool_response>",
                FunctionDefsWrap = @"# Tools

You may call one or more functions to assist with the user query.

You are provided with function signatures within <tools></tools> XML tags:
<tools>
{0}
</tools>",
                PromptFooter = @"For each function call, output the function name and arguments within the following XML format:
<tool_call>{function-name}<arg_key>{arg-key-1}</arg_key><arg_value>{arg-value-1}</arg_value><arg_key>{arg-key-2}</arg_key><arg_value>{arg-value-2}</arg_value>...</tool_call>

Reminder:
- Function calls MUST follow the specified format with a function name at the beginning of <tool_call>
- Then emit each argument as <arg_key>...</arg_key><arg_value>...</arg_value> pairs
- Required parameters MUST be specified
- If no function is needed, answer normally",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterGlm_4_5(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "nvid_nano_v2" => new LLMConfig
            {
                UserReplace = "<SPECIAL_11>User\\\n",
                FunctionReplace = "<SPECIAL_11>User\\\n<TOOL_RESPONSE>[",
                AssistantHeader = "<SPECIAL_11>Assistant\n",
                UserInputTemplate = "<SPECIAL_11>User\\\n{0}",
                AssistantMessageTemplate = "<SPECIAL_11>Assistant\\\n{0}\\\n<SPECIAL_12>\\\n",
                SystemMessageTemplate = "<SPECIAL_10>System\\\n{0}",
                EOTToken = "<SPECIAL_12>",
                FunctionResponseTemplate = "<SPECIAL_11>User\\\n<TOOL_RESPONSE>[{1}]</TOOL_RESPONSE>\\\n",
                NoThinkToken = "/no_think",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionBuilder = "<TOOLCALL>[{\"name\": \"{{function_name}}\", \"arguments\": {{arguments_json}}}]</TOOLCALL>",
                FunctionResponse = "<TOOL_RESPONSE>[{1}]</TOOL_RESPONSE>",
                FunctionDefsWrap = @"You can use the following tools to assist the user if required:
<AVAILABLE_TOOLS>[{0}]</AVAILABLE_TOOLS>",
                PromptFooter = @"If you decide to call any tool(s), use the following format:
<TOOLCALL>[{""name"": ""tool_name1"", ""arguments"": ""tool_args1""}, {""name"": ""tool_name2"", ""arguments"": ""tool_args2""}]</TOOLCALL>

The user will execute tool-calls and return responses from tool(s) in this format:
<TOOL_RESPONSE>[{""tool_response1""}, {""tool_response2""}]</TOOL_RESPONSE>

Based on the tool responses, you can call additional tools if needed, correct tool calls if any errors are found, or just respond to the user.",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterNvid_Nano_V2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },

            "youtu" => new LLMConfig
            {
                UserReplace = "<|User|>",
                FunctionReplace = "<|User|><tool_response>",
                AssistantHeader = "<|Assistant|>",
                UserInputTemplate = "<|User|>{0}",
                AssistantMessageTemplate = "<|Assistant|>{0}<|end_of_text|>",
                SystemMessageTemplate = "{0}",
                EOTToken = "<|end_of_text|>",
                BosToken = "<|begin_of_text|>",
                ThinkBeginToken = "<think>",
                ThinkEndToken = "</think>",
                FunctionResponseTemplate = "<|User|><tool_response>{1}</tool_response>",

                FunctionBuilder = "<tool_call>{{tool_call_json}}</tool_call>",
                FunctionResponse = "<tool_response>{1}</tool_response>",
                FunctionDefsWrap = @"<|begin_of_tool_description|>Tool calling capabilities.
You may call one or more functions to assist with the user query. You have the following functions available:
```json
{0}
```
For tool call returns, you MUST use the following format:
<tool_call>{{""name"": ""function-name"", ""arguments"": {{""param1"": ""value1"", ""param2"": ""value2""}}}}</tool_call>
<|end_of_tool_description|>",
                PromptFooter = "",
                AppendEotToSuffix = false,
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterQwen_3(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },


            "xlam_2" => new LLMConfig
            {
                // User message formatting
                UserReplace = "<|im_start|>user\\\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                FunctionReplace = "<|im_start|>tool\\\n",
                // System prompt formatting
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",

                // Assistant message formatting
                AssistantHeader = "<|im_start|>assistant\n",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",

                // Tool response formatting
                FunctionResponseTemplate = "<|im_start|>tool\\\n{1}",   // {0} is the JSON or string content

                // End of turn token
                EOTToken = "<|im_end|>",

                FunctionBuilder = "[{\"name\":\"{{function_name}}\", \"parameters\":{{arguments_json}}}]",
                FunctionResponse = "[{1}]",
                FunctionDefsWrap = @"You have access to a set of tools. When using tools, make calls in a single JSON array: 

[{{""name"": ""tool_call_name"", ""arguments"": {{...}}}}, ... (additional parallel tool calls as needed)]

If no tool is suitable, state that explicitly. If the user's input lacks required parameters, ask for clarification. Do not interpret or respond until tool results are returned. Once they are available, process them or make additional calls if needed. For tasks that don't require tools, such as casual conversation or general advice, respond directly in plain text. The available tools are:
{0}
",
                PromptFooter = "",
                XmlPromptFooter = _xmlPromptFooter,
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                                    new TokenBroadcasterXlam_2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "lfm_2" => new LLMConfig
            {
                // User message formatting
                UserReplace = "<|im_start|>user\\\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                FunctionReplace = "<|im_start|>tool\\\n",
                // System prompt formatting
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",

                // Assistant message formatting
                AssistantHeader = "<|im_start|>assistant\n",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",

                // Tool response formatting
                FunctionResponseTemplate = "<|im_start|>tool\\\n<|tool_response_start|>{1}<|tool_response_end|>",   // {0} is the JSON or string content

                // End of turn token
                EOTToken = "<|im_end|>",

                FunctionBuilder = "<|tool_call_start|>[{\"name\":\"{{function_name}}\", \"parameters\":{{arguments_json}}}]<|tool_call_end|>",
                FunctionResponse = "<|tool_response_start|>[{1}]<|tool_response_end|>",
                FunctionDefsWrap = @"<|tool_list_start|>{0}<|tool_list_end|>",
                PromptFooter = "",
                XmlPromptFooter = _xmlPromptFooter,
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                                    new TokenBroadcasterLFM_2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            "lfm_2.5" => new LLMConfig
            {
                // User message formatting
                UserReplace = "<|im_start|>user\\\n",
                UserInputTemplate = "<|im_start|>user\\\n{0}",
                FunctionReplace = "<|im_start|>tool\\\n",
                // System prompt formatting
                SystemMessageTemplate = "<|im_start|>system\\\n{0}<|im_end|>",

                // Assistant message formatting
                AssistantHeader = "<|im_start|>assistant\n",
                AssistantMessageTemplate = "<|im_start|>assistant\\\n{0}<|im_end|>",

                // Tool response formatting
                FunctionResponseTemplate = "<|im_start|>tool\\\n<|tool_response_start|>{1}<|tool_response_end|>",

                // End of turn token
                EOTToken = "<|im_end|>",

                FunctionBuilder = "<|tool_call_start|>[{\"name\":\"{{function_name}}\", \"parameters\":{{arguments_json}}}]<|tool_call_end|>",
                FunctionResponse = "<|tool_response_start|>[{1}]<|tool_response_end|>",
                FunctionDefsWrap = @"List of tools: {0}",
                PromptFooter = @"",
                AppendEotToSuffix = true,
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                                    new TokenBroadcasterLFM_2(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },
            // Configuration for gemma_3
            "gemma_3" => new LLMConfig
            {
                UserReplace = "<start_of_turn>user\\\n",
                FunctionReplace = "<start_of_turn>user\\\n```tool_output\\\n",
                AssistantHeader = "<start_of_turn>model\n",
                UserInputTemplate = "<start_of_turn>user\\\n{0}",
                AssistantMessageTemplate = "<start_of_turn>model\\\n{0}<end_of_turn>",
                SystemMessageTemplate = "<start_of_turn>model\\\n{0}<end_of_turn>",
                EOTToken = "<end_of_turn>",
                FunctionResponseTemplate = "<start_of_turn>user\\\n```tool_output\\\n{1}\\\n```",

                FunctionBuilder = "\n```tool_code\n{{tool_call_json}}\n```",
                FunctionResponse = "\n```tool_output\n{1}\n```",
                FunctionDefsWrap = "{0}",
                PromptFooter = "",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterGemma_3(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },

            // Configuration for gemma_4
            "gemma_4" or "gemma-4" => new LLMConfig
            {
                UserReplace = "<|turn>user\\\n",
                FunctionReplace = "<|tool_response>",
                AssistantHeader = "<|turn>model\n",
                UserInputTemplate = "<|turn>user\\\n{0}",
                AssistantMessageTemplate = "<|turn>model\\\n{0}<turn|>\n",
                SystemMessageTemplate = "<|turn>system\\\n{0}<turn|>\n",
                EOTToken = "<turn|>",
                FunctionResponseTemplate = "<|tool_response>response:{0}{{{1}}}<tool_response|>",
                BosToken = "<bos>",

                FunctionBuilder = "<|tool_call>call:{{function_name}}{{arguments_json}}<tool_call|>",
                FunctionResponse = "response:{0}{{{1}}}",
                FunctionDefsWrap = @"# Tools

You have access to the following functions:

<tools>
{0}
</tools>",
                PromptFooter = @"When calling a tool, use the following format:
<|tool_call>call:function_name{arg1:<|""|>value1<|""|>,arg2:<|""|>value2<|""|>}<tool_call|>

Reminder:
- Tool calls MUST follow the specified format
- Required parameters MUST be specified
- Use <|""|> delimiters for string values
- Only call one tool at a time",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterGemma_4(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            },

            "gpt" => new LLMConfig
            {
                UserReplace = "",
                FunctionReplace = "",
                AssistantHeader = "",
                UserInputTemplate = "{0}",
                AssistantMessageTemplate = "{0}",
                SystemMessageTemplate = "{0}",
                EOTToken = "",
                FunctionResponseTemplate = "{1}",

                FunctionBuilder = "{{tool_call_json}}",
                FunctionResponse = "{1}",
                FunctionDefsWrap = "{0}",
                PromptFooter = "",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                       new TokenBroadcasterStandard(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

            },

            "gpt_oss" => new LLMConfig
            {
                // Core per-turn wrappers
                UserReplace = "<|start|>user<|message|>",
                FunctionReplace = "<|start|>functions",
                AssistantHeader = "<|start|>assistant<|channel|>final\n\n",

                // Full message templates (produce complete framed segments)
                UserInputTemplate = "<|start|>user<|message|>{0}<|end|>",
                AssistantMessageTemplate = "<|start|>assistant<|channel|>final<|message|>{0}<|end|>",
                SystemMessageTemplate = "<|start|>system<|message|>{0}<|end|>",

                // Segment terminators
                EOTToken = "<|end|>",

                // Tool *result* you send back to the model
                // {0} must be "functions.NAME", {1} is raw JSON (string)
                FunctionResponseTemplate =
                    "{0} to=assistant<|channel|>commentary<|message|>{1}<|end|>",

                // Tool *call* envelopes the model emits
                // {0} must be "functions.NAME"
                // {1} is JSON arguments
                FunctionBuilder =
                    "function.commentary to={{function_name}} <|constrain|>json<|message|>{{arguments_json}}",

                FunctionResponse = "{1}",
                FunctionDefsWrap = "{0}",

                // Optional footer (helps the model keep channels straight)
                PromptFooter =@"",

                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                       new TokenBroadcasterGptOss(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

            },


            "blank" => new LLMConfig
            {
                UserReplace = "",
                FunctionReplace = "",
                AssistantHeader = "",
                UserInputTemplate = "{0}",
                AssistantMessageTemplate = "{0}",
                SystemMessageTemplate = "{0}",
                EOTToken = "",
                FunctionResponseTemplate = "{1}",

                FunctionBuilder = "{{tool_call_json}}",
                FunctionResponse = "{1}",
                FunctionDefsWrap = "{0}",
                PromptFooter = "",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                       new TokenBroadcasterStandard(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)

            },

            // Configuration for standard
            _ => new LLMConfig
            {
                UserReplace = "",
                FunctionReplace = "Function Call :",
                AssistantHeader = "",
                UserInputTemplate = "Function Call : {0}",
                AssistantMessageTemplate = "{0}",
                SystemMessageTemplate = "{0}",
                EOTToken = "",
                FunctionResponseTemplate = "FUNCTION RESPONSE: {1}",

                FunctionBuilder = "FUNCTION CALL: {{tool_call_json}}",
                FunctionResponse = "FUNCTION RESPONSE: {1}",
                FunctionDefsWrap = "{0}",
                PromptFooter = "",
                CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) =>
                        new TokenBroadcasterStandard(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)
            }
        };

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
    public string SystemMessageTemplate { get; set; } = string.Empty;
    public string EOTToken { get; set; } = string.Empty;
    public string EOMToken { get; set; } = string.Empty;
    public string ThinkBeginToken { get; set; } = string.Empty;
    public string ThinkEndToken { get; set; } = string.Empty;
    public string FunctionResponseTemplate { get; set; } = string.Empty;
    public string FunctionResponse { get; set; } = string.Empty;
    public string FunctionDefsWrap { get; set; } = string.Empty;
    public string FunctionBuilder { get; set; } = string.Empty;
    public string PromptFooter { get; set; } = string.Empty;
    public string XmlPromptFooter { get; set; } = string.Empty;
    public string NoThinkToken { get; set; } = string.Empty;
    public string ReversePrompt { get; set; } = string.Empty;
    public string ExtraReversePrompt { get; set; } = string.Empty;
    public string BosToken { get; set; } = string.Empty;
    public bool AppendEotToSuffix { get; set; } = true;
    public Func<ILLMResponseProcessor, ILogger, bool, ITokenBroadcaster> CreateBroadcaster { get; set; } =
            (_, _, _) => throw new InvalidOperationException("No broadcaster defined for this LLMConfig.");

}

#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class LLMConfigSpec:
    key: str
    user_replace: str = ""
    function_replace: str = ""
    assistant_header: str = ""
    user_input_template: str = ""
    assistant_message_template: str = ""
    system_message_template: str = ""
    eot_token: str = ""
    eom_token: str = ""
    think_begin_token: str = ""
    think_end_token: str = ""
    function_response_template: str = ""
    function_response: str = ""
    function_defs_wrap: str = ""
    function_builder: str = ""
    prompt_footer: str = ""
    xml_prompt_footer: str = ""
    no_think_token: str = ""
    reverse_prompt: str = ""
    extra_reverse_prompt: str = ""
    broadcaster: str = ""


def detect_style(template: str) -> Optional[str]:
    t = template
    if "List of tools: [" in t and "<|im_start|>" in t and "<|im_end|>" in t:
        return "lfm_2.5"
    if "<|User|>" in t and "<|Assistant|>" in t and "<|end_of_text|>" in t:
        return "youtu"
    if "<start_of_turn>" in t and "<end_of_turn>" in t:
        return "gemma_3"
    if "<|tool_call_start|>" in t and "<|tool_call_end|>" in t:
        return "lfm_2"
    if "<function_calls>" in t and "<invoke" in t:
        return "deepseek_3.2_exp"
    if "<|start_header_id|>" in t and "<|eot_id|>" in t:
        return "llama_3.2"
    if "<|im_start|>user<|im_sep|>" in t and "<|im_end|>" in t:
        return "phi_4"
    if "<|user|>" in t and "<|assistant|>" in t and "<|end|>" in t:
        return "phi_4_mini"
    if "<|im_start|>" in t and "<|im_end|>" in t:
        if "<think>" in t or "</think>" in t:
            return "qwen_3"
        if "<tool_call>" in t or "<tool_response>" in t:
            return "qwen_2.5"
    if "xlam" in t.lower():
        return "xlam_2"
    return None


def style_to_config(style: str) -> LLMConfigSpec:
    if style == "qwen_3":
        return LLMConfigSpec(
            key="qwen_3",
            user_replace="<|im_start|>user\\\n",
            function_replace="<|im_start|>user\\\n<tool_response>",
            assistant_header="<|im_start|>assistant\n",
            user_input_template="<|im_start|>user\\\n{0}",
            assistant_message_template="<|im_start|>assistant\\\n{0}<|im_end|>",
            system_message_template="<|im_start|>system\\\n{0}<|im_end|>",
            eot_token="<|im_end|>",
            function_response_template="<|im_start|>user\\\n<tool_response>\\\n{1}\\\n</tool_response>",
            think_begin_token="<think>",
            think_end_token="</think>",
            function_builder="<tool_call>\n{1}\n</tool_call>",
            function_response="<tool_response>{1}</tool_response>",
            function_defs_wrap="# Tools\n\nYou may call one or more functions to assist with the user query.\n\nYou are provided with function signatures within <tools></tools> XML tags:\n<tools>\n{0}\n</tools>",
            prompt_footer="For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:\n<tool_call>\n{\"name\": <function-name>, \"arguments\": <args-json-object>}\n</tool_call>\nReminder:\n- Function calls MUST follow the specified format : <tool_call> {\"name\": <function-name>, \"arguments\": <args-json-object>} </tool_call>\n- The function call repsonses are between tags <tool_response> and </tool_response> \n- Required parameters MUST be specified\n- Only call one function at a time\n- Important: You will call functions only when necessary. Checking with the user before calling more functions.\n",
            broadcaster="qwen_3",
        )
    if style == "qwen_2.5":
        return LLMConfigSpec(
            key="qwen_2.5",
            user_replace="<|im_start|>user\\\n",
            function_replace="<|im_start|>user\\\n<tool_response>",
            assistant_header="<|im_start|>assistant\n",
            user_input_template="<|im_start|>user\\\n{0}",
            assistant_message_template="<|im_start|>assistant\\\n{0}<|im_end|>",
            system_message_template="<|im_start|>system\\\n{0}<|im_end|>",
            eot_token="<|im_end|>",
            function_response_template="<|im_start|>user\\\n<tool_response>\\\n{1}\\\n</tool_response>",
            function_builder="<tool_call>\n{1}\n</tool_call>",
            function_response="<tool_response>{1}</tool_response>",
            function_defs_wrap="# Tools\n\nYou may call one or more functions to assist with the user query.\n\nYou are provided with function signatures within <tools></tools> XML tags:\n<tools>\n{0}\n</tools>",
            prompt_footer="For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:\n<tool_call>\n{\"name\": <function-name>, \"arguments\": <args-json-object>}\n</tool_call>\nReminder:\n- Function calls MUST follow the specified format : <tool_call> {\"name\": <function-name>, \"arguments\": <args-json-object>} </tool_call>\n- The function call repsonses are between tags <tool_response> and </tool_response> \n- Required parameters MUST be specified\n- Only call one function at a time\n- Important: You will call functions only when necessary. Checking with the user before calling more functions.\n",
            broadcaster="qwen_2.5",
        )
    if style == "llama_3.2":
        return LLMConfigSpec(
            key="llama_3.2",
            user_replace="<|start_header_id|>user<|end_header_id|>\\\n\\\n",
            function_replace="<|start_header_id|>ipython<|end_header_id|>\\\n\\\n",
            assistant_header="<|start_header_id|>assistant<|end_header_id|>\n\n",
            user_input_template="<|start_header_id|>user<|end_header_id|>\\\n\\\n{0}",
            assistant_message_template="<|start_header_id|>assistant<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            system_message_template="<|start_header_id|>system<|end_header_id|>\\\n\\\n{0}<|eot_id|>",
            eot_token="<|eot_id|>",
            eom_token="<|eom_id|>",
            function_response_template="<|start_header_id|>ipython<|end_header_id|>\\\n\\\n{1}",
            function_builder="{{\"name\":\"{0}\", \"parameters\":{1}}}",
            function_response="{1}",
            function_defs_wrap="Ensure that any function calls you use align with the user's request. Use only the functions necessary for the task. For failed function calls, provide feedback about the issue before retrying or switching functions.\n\nHere is a list of functions in JSON format that you can invoke:\n\n{0}",
            broadcaster="llama_3.2",
        )
    if style == "deepseek_3.2_exp":
        return LLMConfigSpec(
            key="deepseek_3.2_exp",
            user_replace="<|User|>",
            function_replace="<function_calls>",
            assistant_header="<|Assistant|></think>",
            user_input_template="<|User|>{0}",
            assistant_message_template="<|Assistant|></think>{0}<|end_of_sentence|>",
            system_message_template="{0}<|end_of_sentence|>",
            eot_token="<|end_of_sentence|>",
            think_begin_token="<think>",
            think_end_token="</think>",
            function_response_template="{1}",
            function_builder="<function_calls>\n<invoke name={0}>\n{1}>\n</invoke>\n</function_calls>",
            function_response="{1}",
            function_defs_wrap="Available tools:\n{0}",
            prompt_footer="When you must call a function, respond with XML in this form:\n<function_calls>\n  <invoke name=\"function_name\">\n    <parameter name=\"argument_name\">argument_value</parameter>\n  </invoke>\n</function_calls>",
            broadcaster="deepseek_3.2_exp",
        )
    if style == "phi_4":
        return LLMConfigSpec(
            key="phi_4",
            user_replace="<|im_start|>user<|im_sep|>\\\n",
            function_replace="<|im_start|>user<|im_sep|>\\\n<function_response>\\\n",
            assistant_header="<|im_start|>assistant<|im_sep|>\n",
            user_input_template="<|im_start|>user<|im_sep|>\\\n{0}",
            assistant_message_template="<|im_start|>assistant<|im_sep|>\\\n{0}<|im_end|>",
            system_message_template="<|im_start|>system<|im_sep|>\\\n{0}<|im_end|>",
            eot_token="<|im_end|>",
            function_response_template="<|im_start|>user<|im_sep|>\\\n<function_response name={0}>\\\n{1}\\\n</function_response>",
            think_begin_token="<reasoning>",
            think_end_token="</reasoning>",
            function_builder="<function={0}>{1}</function>",
            function_response="{1}",
            function_defs_wrap="You have access to the following functions:\n\n{0}",
            broadcaster="phi_4",
        )
    if style == "phi_4_mini":
        return LLMConfigSpec(
            key="phi_4_mini",
            user_replace="<|user|>\\\n",
            function_replace="<|tool_response|>",
            assistant_header="<|assistant|>\n",
            user_input_template="<|user|>\\\n{0}",
            assistant_message_template="<|assistant|>\\\n{0}<|end|>",
            system_message_template="<|system|>\\\n{0}<|end|>",
            eot_token="<|end|>",
            function_response_template="<|tool_response|>[{1}]",
            function_builder="<tool_call>{1}</tool_call>",
            function_response="<|tool_response|>[{1}]",
            function_defs_wrap="You are a helpful assistant with some tools.\n<|tool|>\n{0}\n<|/tool|>",
            prompt_footer="For each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:\n<tool_call>\n{\"name\": <function-name>, \"arguments\": <args-json-object>}\n</tool_call>\nReminder:\n- Function calls MUST follow the specified format : <tool_call> {\"name\": <function-name>, \"arguments\": <args-json-object>} </tool_call>\n- The function call repsonses after the tag <tool_response>\n- Required parameters MUST be specified\n- Only call one function at a time\n- Important: You will call functions only when necessary. Checking with the user before calling more functions.\n",
            broadcaster="phi_4_mini",
        )
    if style == "xlam_2":
        return LLMConfigSpec(
            key="xlam_2",
            user_replace="<|im_start|>user\\\n",
            function_replace="<|im_start|>tool\\\n",
            assistant_header="<|im_start|>assistant\n",
            user_input_template="<|im_start|>user\\\n{0}",
            assistant_message_template="<|im_start|>assistant\\\n{0}<|im_end|>",
            system_message_template="<|im_start|>system\\\n{0}<|im_end|>",
            eot_token="<|im_end|>",
            function_response_template="<|im_start|>tool\\\n{1}",
            function_builder="[{\"name\":\"{0}\", \"parameters\":{1}}]",
            function_response="[{1}]",
            function_defs_wrap="You have access to a set of tools. When using tools, make calls in a single JSON array: \n\n[{\"name\": \"tool_call_name\", \"arguments\": {\"arg1\": \"value1\", \"arg2\": \"value2\"}}, ... (additional parallel tool calls as needed)]\n\nIf no tool is suitable, state that explicitly. If the user's input lacks required parameters, ask for clarification. Do not interpret or respond until tool results are returned. Once they are available, process them or make additional calls if needed. For tasks that don't require tools, such as casual conversation or general advice, respond directly in plain text. The available tools are:\n{0}\n",
            broadcaster="xlam_2",
        )
    if style == "lfm_2":
        return LLMConfigSpec(
            key="lfm_2",
            user_replace="<|im_start|>user\\\n",
            function_replace="<|im_start|>tool\\\n",
            assistant_header="<|im_start|>assistant\n",
            user_input_template="<|im_start|>user\\\n{0}",
            assistant_message_template="<|im_start|>assistant\\\n{0}<|im_end|>",
            system_message_template="<|im_start|>system\\\n{0}<|im_end|>",
            eot_token="<|im_end|>",
            function_response_template="<|im_start|>tool\\\n<|tool_response_start|>{1}<|tool_response_end|>",
            function_builder="<|tool_call_start|>[{\"name\":\"{0}\", \"parameters\":{1}}]<|tool_call_end|>",
            function_response="<|tool_response_start|>[{1}]<|tool_response_end|>",
            function_defs_wrap="<|tool_list_start|>{0}<|tool_list_end|>",
            broadcaster="lfm_2",
        )
    if style == "lfm_2.5":
        return LLMConfigSpec(
            key="lfm_2.5",
            user_replace="<|im_start|>user\\\n",
            function_replace="<|im_start|>tool\\\n",
            assistant_header="<|im_start|>assistant\n",
            user_input_template="<|im_start|>user\\\n{0}",
            assistant_message_template="<|im_start|>assistant\\\n{0}<|im_end|>",
            system_message_template="<|im_start|>system\\\n{0}<|im_end|>",
            eot_token="<|im_end|>",
            function_response_template="<|im_start|>tool\\\n<|tool_response_start|>{1}<|tool_response_end|>",
            function_builder="<|tool_call_start|>[{\"name\":\"{0}\", \"parameters\":{1}}]<|tool_call_end|>",
            function_response="<|tool_response_start|>[{1}]<|tool_response_end|>",
            function_defs_wrap="List of tools: [{0}]",
            prompt_footer="When calling tools, return python-style calls inside the wrapper:\n<|tool_call_start|>[function_name(arg1=\"value1\", arg2=123)]<|tool_call_end|>\nYou may also return a JSON list of tool calls inside the same wrapper.",
            broadcaster="lfm_2",
        )
    if style == "gemma_3":
        return LLMConfigSpec(
            key="gemma_3",
            user_replace="<start_of_turn>user\\\n",
            function_replace="<start_of_turn>user\\\n```tool_output\\\n",
            assistant_header="<start_of_turn>model\n",
            user_input_template="<start_of_turn>user\\\n{0}",
            assistant_message_template="<start_of_turn>model\\\n{0}<end_of_turn>",
            system_message_template="<start_of_turn>model\\\n{0}<end_of_turn>",
            eot_token="<end_of_turn>",
            function_response_template="<start_of_turn>user\\\n```tool_output\\\n{1}\\\n```",
            function_builder="\n```tool_code\n{1}\n```",
            function_response="\n```tool_output\n{1}\n```",
            broadcaster="gemma_3",
        )
    if style == "youtu":
        return LLMConfigSpec(
            key="youtu",
            user_replace="<|User|>",
            function_replace="<|User|><tool_response>",
            assistant_header="<|Assistant|>",
            user_input_template="<|User|>{0}",
            assistant_message_template="<|Assistant|>{0}<|end_of_text|>",
            system_message_template="{0}",
            eot_token="<|end_of_text|>",
            think_begin_token="<think>",
            think_end_token="</think>",
            function_response_template="<|User|><tool_response>{1}</tool_response>",
            function_builder="<tool_call>{1}</tool_call>",
            function_response="<tool_response>{1}</tool_response>",
            function_defs_wrap="<|begin_of_tool_description|>Tool calling capabilities.\nYou may call one or more functions to assist with the user query. You have the following functions available:\n```json\n{0}\n```\nFor tool call returns, you MUST use the following format:\n<tool_call>{\"name\": \"function-name\", \"arguments\": {\"param1\": \"value1\", \"param2\": \"value2\"}}</tool_call>\n<|end_of_tool_description|>",
            broadcaster="qwen_3",
        )
    raise ValueError(f"Unsupported style: {style}")


def broadcaster_to_class(broadcaster: str) -> Optional[str]:
    return {
        "qwen_3": "TokenBroadcasterQwen_3",
        "qwen_2.5": "TokenBroadcasterQwen_2_5",
        "llama_3.2": "TokenBroadcasterLlama_3_2",
        "deepseek_3.2_exp": "TokenBroadcasterDeepseek_3_2_Exp",
        "phi_4": "TokenBroadcasterPhi_4",
        "phi_4_mini": "TokenBroadcasterPhi_4_Mini",
        "xlam_2": "TokenBroadcasterXlam2",
        "lfm_2": "TokenBroadcasterLFM_2",
        "lfm_2.5": "TokenBroadcasterLFM_2",
        "gemma_3": "TokenBroadcasterGemma_3",
        "youtu": "TokenBroadcasterQwen_3",
    }.get(broadcaster)


def to_csharp(spec: LLMConfigSpec) -> str:
    def q(value: str) -> str:
        if "\n" in value or "\r" in value:
            return '@"' + value.replace('"', '""') + '"'
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines = [f"\"{spec.key}\" => new LLMConfig", "{"]

    def add(name: str, val: str) -> None:
        lines.append(f"    {name} = {q(val)},")

    add("UserReplace", spec.user_replace)
    add("FunctionReplace", spec.function_replace)
    add("AssistantHeader", spec.assistant_header)
    add("UserInputTemplate", spec.user_input_template)
    add("AssistantMessageTemplate", spec.assistant_message_template)
    add("SystemMessageTemplate", spec.system_message_template)
    add("EOTToken", spec.eot_token)
    if spec.eom_token:
        add("EOMToken", spec.eom_token)
    if spec.think_begin_token:
        add("ThinkBeginToken", spec.think_begin_token)
    if spec.think_end_token:
        add("ThinkEndToken", spec.think_end_token)
    add("FunctionResponseTemplate", spec.function_response_template)
    add("FunctionBuilder", spec.function_builder)
    add("FunctionResponse", spec.function_response)
    add("FunctionDefsWrap", spec.function_defs_wrap)
    add("PromptFooter", spec.prompt_footer)
    if spec.xml_prompt_footer:
        add("XmlPromptFooter", spec.xml_prompt_footer)
    if spec.no_think_token:
        add("NoThinkToken", spec.no_think_token)
    if spec.reverse_prompt:
        add("ReversePrompt", spec.reverse_prompt)
    if spec.extra_reverse_prompt:
        add("ExtraReversePrompt", spec.extra_reverse_prompt)

    if spec.broadcaster:
        class_name = broadcaster_to_class(spec.broadcaster)
        if class_name:
            lines.append(
                f"    CreateBroadcaster = (responseProcessor, logger, xmlFunctionParsing) => "
                f"new {class_name}(responseProcessor, logger, xmlFunctionParsing, IgnoreParameters)"
            )

    lines.append("}")
    return "\n".join(lines)


def load_style_map(path: Optional[str]) -> dict:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("Style map must be a JSON object keyed by style.")
    return data


def build_from_style_map(style_map: dict, style: str) -> Optional[LLMConfigSpec]:
    raw = style_map.get(style)
    if not isinstance(raw, dict):
        return None
    if "key" not in raw:
        raw = {"key": style, **raw}
    return LLMConfigSpec(**raw)


def extract_tokens(template: str) -> list:
    tokens = set(re.findall(r"<\\|[^>]+\\|>", template))
    return sorted(tokens)


def infer_broadcaster(template: str) -> str:
    t = template
    if "List of tools: [" in t and "<|im_start|>" in t and "<|im_end|>" in t:
        return "lfm_2"
    if "<tool_calls>" in t and "</tool_calls>" in t:
        return "xlam_2"
    if "<tool_call>" in t and "</tool_call>" in t:
        return "qwen_3"
    if "<function_calls>" in t and "<invoke" in t:
        return "deepseek_3.2_exp"
    if "<|tool_call_start|>" in t and "<|tool_call_end|>" in t:
        return "lfm_2"
    if "<function=" in t and "</function>" in t:
        return "func_3.1"
    if "<|start_header_id|>" in t and "<|eot_id|>" in t:
        return "llama_3.2"
    if "<|user|>" in t and "<|assistant|>" in t and "<|end|>" in t:
        return "phi_4_mini"
    if "<|im_start|>user<|im_sep|>" in t:
        return "phi_4"
    if "<start_of_turn>" in t and "<end_of_turn>" in t:
        return "gemma_3"
    if "<|im_start|>" in t and "<|im_end|>" in t:
        return "qwen_2.5"
    return ""


def infer_config(template: str, key: str) -> LLMConfigSpec:
    t = template
    tokens = extract_tokens(t)

    def has(s: str) -> bool:
        return s in t

    def has_lit(s: str) -> bool:
        return s in t

    def newline_for(pattern: str) -> str:
        if pattern + "\\n" in t or pattern + "\n" in t:
            return "\\\n"
        return ""

    eot_candidates = [
        "<|end_of_text|>",
        "<|eot_id|>",
        "<|end_of_sentence|>",
        "<|im_end|>",
        "<|end|>",
        "<end_of_turn>",
    ]
    eot_token = ""
    for c in eot_candidates:
        if has(c):
            eot_token = c
            break

    user_replace = ""
    assistant_header = ""
    system_template = ""
    user_template = ""
    assistant_template = ""
    function_replace = ""
    function_response_template = ""

    if "<|User|>" in t:
        user_replace = "<|User|>"
        user_template = "<|User|>{0}"
    if "<|Assistant|>" in t:
        assistant_header = "<|Assistant|>"
        assistant_template = "<|Assistant|>{0}" + (eot_token or "")
    if "<|System|>" in t:
        system_template = "<|System|>{0}" + (eot_token or "")

    if "<|im_start|>" in t and "<|im_end|>" in t:
        user_nl = newline_for("<|im_start|>user")
        assistant_nl = newline_for("<|im_start|>assistant")
        system_nl = newline_for("<|im_start|>system")

        user_replace = "<|im_start|>user" + user_nl
        user_template = "<|im_start|>user" + user_nl + "{0}"
        assistant_header = "<|im_start|>assistant" + (assistant_nl or "\n")
        assistant_template = "<|im_start|>assistant" + assistant_nl + "{0}" + (eot_token or "")
        system_template = "<|im_start|>system" + system_nl + "{0}" + (eot_token or "")

        if "<tool_response>" in t:
            function_replace = "<|im_start|>user" + user_nl + "<tool_response>"
            function_response_template = (
                "<|im_start|>user" + user_nl + "<tool_response>\\\n{1}\\\n</tool_response>"
            )

    if "<|start_header_id|>" in t and "<|end_header_id|>" in t:
        sep = "\\\n\\\n" if "\\n\\n" in t or "\n\n" in t else "\\\n"
        user_replace = "<|start_header_id|>user<|end_header_id|>" + sep
        function_replace = "<|start_header_id|>tool<|end_header_id|>" + sep
        assistant_header = "<|start_header_id|>assistant<|end_header_id|>\n\n"
        user_template = "<|start_header_id|>user<|end_header_id|>" + sep + "{0}"
        assistant_template = "<|start_header_id|>assistant<|end_header_id|>" + sep + "{0}" + (eot_token or "")
        system_template = "<|start_header_id|>system<|end_header_id|>" + sep + "{0}" + (eot_token or "")

    if "<|user|>" in t and "<|assistant|>" in t and "<|end|>" in t:
        user_replace = "<|user|>\\\n"
        user_template = "<|user|>\\\n{0}"
        assistant_header = "<|assistant|>\n"
        assistant_template = "<|assistant|>\\\n{0}<|end|>"
        system_template = "<|system|>\\\n{0}<|end|>"

    if "<tool_response>" in t and not function_response_template:
        if user_replace:
            function_replace = user_replace + "<tool_response>"
            function_response_template = user_replace + "<tool_response>{1}</tool_response>"
        else:
            function_response_template = "<tool_response>{1}</tool_response>"

    function_builder = ""
    if "<tool_call>" in t and "</tool_call>" in t:
        function_builder = "<tool_call>\n{1}\n</tool_call>"
    elif "<function=" in t and "</function>" in t:
        function_builder = "<function={0}>{1}</function>"
    elif "<function_calls>" in t and "<invoke" in t:
        function_builder = "<function_calls>\n<invoke name={0}>\n{1}>\n</invoke>\n</function_calls>"

    function_response = ""
    if "<tool_response>" in t and "</tool_response>" in t:
        function_response = "<tool_response>{1}</tool_response>"

    think_begin = "<think>" if "<think>" in t else ""
    think_end = "</think>" if "</think>" in t else ""

    if not system_template:
        system_template = "{0}" + (eot_token or "")

    if not assistant_template and assistant_header:
        assistant_template = assistant_header + "{0}" + (eot_token or "")

    if not user_template and user_replace:
        user_template = user_replace + "{0}"

    if not user_replace and "<|User|>" in tokens:
        user_replace = "<|User|>"
        user_template = "<|User|>{0}"

    function_defs_wrap = "{0}"
    if "List of tools: [" in t:
        function_defs_wrap = "List of tools: [{0}]"
    if "<|begin_of_tool_description|>" in t and "<|end_of_tool_description|>" in t:
        function_defs_wrap = "<|begin_of_tool_description|>{0}<|end_of_tool_description|>"

    if function_response_template == "" and function_response:
        function_response_template = function_response

    spec = LLMConfigSpec(
        key=key,
        user_replace=user_replace,
        function_replace=function_replace,
        assistant_header=assistant_header,
        user_input_template=user_template,
        assistant_message_template=assistant_template,
        system_message_template=system_template,
        eot_token=eot_token,
        think_begin_token=think_begin,
        think_end_token=think_end,
        function_response_template=function_response_template,
        function_response=function_response,
        function_defs_wrap=function_defs_wrap,
        function_builder=function_builder,
        broadcaster=infer_broadcaster(t),
    )

    return spec


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert a Jinja chat template to an LLMConfig skeleton.")
    parser.add_argument("template", help="Path to Jinja template file")
    parser.add_argument("--style", help="Force a style key (e.g., qwen_3, xlam_2)")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of C# snippet")
    parser.add_argument("--style-map", help="Path to JSON file with custom style mappings")
    parser.add_argument("--tokens", action="store_true", help="Print detected special tokens and exit")
    parser.add_argument("--key", help="Key name for inferred configs (default: inferred-style)")
    args = parser.parse_args()

    with open(args.template, "r", encoding="utf-8") as f:
        content = f.read()

    if args.tokens:
        print("\n".join(extract_tokens(content)))
        return

    style_map = load_style_map(args.style_map)

    style = args.style or detect_style(content)
    spec = None
    if style:
        spec = build_from_style_map(style_map, style) or style_to_config(style)
    else:
        key = args.key or "inferred-style"
        spec = infer_config(content, key)
        print("warning: using heuristic inference for unknown style", file=sys.stderr)
        if not spec.broadcaster:
            print("warning: could not infer broadcaster; set it manually", file=sys.stderr)
    if style and spec and not spec.broadcaster:
        inferred = infer_broadcaster(content)
        if inferred:
            spec.broadcaster = inferred
        else:
            print("warning: could not infer broadcaster; set it manually", file=sys.stderr)

    if args.json:
        print(json.dumps(asdict(spec), indent=2))
    else:
        print(to_csharp(spec))


if __name__ == "__main__":
    main()

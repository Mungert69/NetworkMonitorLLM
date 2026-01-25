using NetworkMonitor.Objects.ServiceMessage;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using System.Collections.Generic;
using System;
using System.Text;

namespace NetworkMonitor.LLM.Services
{
    public class AgentFlowExpertToolsBuilder : ToolsBuilderBase
    {
        private readonly string _prompt;
        private const string PromptHeader = @"
### Agenic-Flow Graph JSON Schema

```json
{
  ""$schema"": ""https://json-schema.org/draft/2020-12/schema"",
  ""$id"": ""https://example.com/agent-graph.schema.json"",
  ""title"": ""Agenic-Flow Graph"",
  ""type"": ""object"",
  ""required"": [""version"", ""startNode"", ""nodes"", ""toolSpecs""],
  ""additionalProperties"": false,
  ""properties"": {
    ""version"": { ""type"": ""integer"", ""const"": 1 },
    ""startNode"": { ""type"": ""string"", ""minLength"": 1 },
    ""initState"": { ""type"": ""object"", ""additionalProperties"": true },
    ""nodes"": {
      ""type"": ""array"",
      ""minItems"": 1,
      ""items"": { ""$ref"": ""#/$defs/NodeConfig"" }
    },
    ""toolSpecs"": {
      ""type"": ""array"",
      ""minItems"": 1,
      ""items"": {
        ""oneOf"": [
          { ""$ref"": ""#/$defs/ToolBuilderSpec"" },
          {
            ""type"": ""object"",
            ""required"": [""$ref""],
            ""additionalProperties"": false,
            ""properties"": { ""$ref"": { ""type"": ""string"", ""minLength"": 1 } }
          }
        ]
      }
    }
  },
  ""$defs"": {
    ""NodeConfig"": {
      ""type"": ""object"",
      ""required"": [""id"", ""type"", ""toolSpecId"", ""promptTemplate""],
      ""additionalProperties"": false,
      ""properties"": {
        ""id"": { ""type"": ""string"", ""minLength"": 1 },
        ""type"": { ""type"": ""string"", ""enum"": [""template-llm"", ""branch-llm""] },
        ""toolSpecId"": { ""type"": ""string"", ""minLength"": 1 },
        ""promptTemplate"": { ""type"": ""string"", ""minLength"": 1 },
        ""next"": { ""type"": [""string"", ""null""] },
        ""outputs"": {
          ""type"": ""array"",
          ""description"": ""Saved to state (template-llm only)"",
          ""items"": { ""type"": ""string"", ""minLength"": 1 },
          ""uniqueItems"": true
        },
        ""constants"": { ""type"": ""object"", ""additionalProperties"": { ""type"": ""string"" } },
        ""defaults"": { ""type"": ""object"", ""additionalProperties"": { ""type"": ""string"" } },
        ""requires"": {
          ""type"": ""array"",
          ""items"": { ""type"": ""string"", ""minLength"": 1 },
          ""uniqueItems"": true
        },
        ""timeoutSec"": { ""type"": ""integer"", ""minimum"": 1 },
        ""branches"": {
          ""type"": ""object"",
          ""description"": ""Status -> next-node map (branch-llm only)"",
          ""additionalProperties"": { ""type"": [""string"", ""null""] }
        }
      },
      ""oneOf"": [
        { ""properties"": { ""type"": { ""const"": ""template-llm"" } } },
        {
          ""properties"": { ""type"": { ""const"": ""branch-llm"" } },
          ""not"": { ""required"": [""outputs""] }
        }
      ]
    },
    ""ToolBuilderSpec"": {
      ""type"": ""object"",
      ""required"": [""id"", ""systemPrompt""],
      ""additionalProperties"": false,
      ""properties"": {
        ""id"": { ""type"": ""string"", ""minLength"": 1 },
        ""systemPrompt"": { ""type"": ""string"", ""minLength"": 1 },
        ""functions"": {
          ""type"": ""array"",
          ""items"": { ""type"": ""string"", ""minLength"": 1 },
          ""uniqueItems"": true
        },
        ""cmdProcessorFunctions"": {
          ""type"": ""array"",
          ""items"": { ""$ref"": ""#/$defs/CmdProcessorFunctionSpec"" }
        }
      }
    },
    ""CmdProcessorFunctionSpec"": {
      ""type"": ""object"",
      ""required"": [""name"", ""parameters""],
      ""additionalProperties"": false,
      ""properties"": {
        ""name"": { ""type"": ""string"", ""minLength"": 1 },
        ""description"": { ""type"": ""string"" },
        ""parameters"": {
          ""type"": ""array"",
          ""minItems"": 1,
          ""items"": { ""$ref"": ""#/$defs/CmdProcessorFunctionParameter"" }
        }
      }
    },
    ""CmdProcessorFunctionParameter"": {
      ""type"": ""object"",
      ""required"": [""name"", ""type""],
      ""additionalProperties"": false,
      ""properties"": {
        ""name"": { ""type"": ""string"", ""minLength"": 1 },
        ""type"": { ""type"": ""string"", ""minLength"": 1 },
        ""description"": { ""type"": ""string"" }
      }
    }
  }
}
```

When creating or editing an agent flow follow these rules.

1. TOP-LEVEL RULES
1.1 The root must include: ""version"": 1, ""startNode"", ""nodes"", ""toolSpecs"".
1.2 Choose a unique startNode id that appears in nodes.
1.3 initState is optional. Add {""RetryLimit"": 2} when you want automatic retries.
1.4 Every toolSpecId referenced by a node must have a matching entry in toolSpecs.
1.5 All strings are plain UTF-8. Never emit markdown fences, back-ticks, or comments.

2. NODE DESIGN
template-llm nodes
- Required keys: id, type, toolSpecId, promptTemplate
- promptTemplate: Instructions only; do not append output formatting instructions.
- Declare outputs array. Outputs are validated and stored in state as key/value pairs.

branch-llm nodes
- Same required keys plus branches.
- Output status only. Map status to next node. Example: {""success"": null, ""retry"": ""id_of_node_to_repeat"", ""fail"": null}.
- Retry consumes initState.RetryLimit.

2B. BRANCH-LLM NODES: DECISION ONLY, NO STATE OUTPUT
- outputs property is forbidden on branch-llm nodes.
- Output format: { ""status"": ""success|retry|fail"", ""reason"": ""<details>"" }.

3. TOOL SPEC REQUIREMENTS
- Each toolSpecs entry must include: id, systemPrompt.
- functions is subset of available functions actually used by that node.
- cmdProcessorFunctions only if the node will call dynamically created cmd processor functions.

7. EXECUTION AND STORAGE
- After you create a flow JSON, you MUST call add_agent_flow to save it.
- Do not return the flow JSON unless the user explicitly asks to see it.
- If the user asks to list, get, or delete flows, call list_agent_flows/get_agent_flow/delete_agent_flow directly and return the tool result. Do NOT create a flow JSON for those requests.

4. PROMPT AND PLACEHOLDER RULES
4.1 Use placeholders exactly as {{Key}}, {{Key|Fallback}}, or {{Prompts.Method(args)}}.
4.2 Prompt text must be self-contained; do not mention schemas or internal code.

5. VALIDATION AND STATE ALIGNMENT
5.1 Every key in outputs is validated and stored in state if present.
5.2 Later nodes must reference the stored outputs in their required fields.
5.3 Missing or mis-named keys cause runtime failure.

6. FINISH CRITERIA
- Reply with exactly one JSON object that conforms to the schema.
- No trailing commas, extra keys, wrapper arrays, or explanatory text.
- Any deviation causes the runtime to reject the graph.

7. HARD REQUIREMENTS CHECKLIST
- Top-level required keys: version, startNode, nodes, toolSpecs.
- Each node must include: id, type, toolSpecId, promptTemplate.
- template-llm nodes must include outputs.
- branch-llm nodes must include branches and must not include outputs.
- Each toolSpec must include: id, systemPrompt.
- Every toolSpecId referenced by nodes must exist in toolSpecs.

";

        private const string PromptRules = @"
You are the Agent Flow Expert for Network Monitor and the manager of agent flows. You handle the full lifecycle and return the results of your actions to the caller.

What you do:
- Create new flows from a user goal.
- Edit existing flows when asked to change or update a flow.
- List available flows.
- Delete flows when asked.
- Run saved flows when asked.

How you operate:
- For create or edit: build the flow JSON, save it with add_agent_flow (overwrite=true when updating).
- For list/get/delete: call list_agent_flows/get_agent_flow/delete_agent_flow directly and return the tool output. Do NOT generate a flow JSON for those requests.
- For run: call run_agent_flow with the flow name and required arguments.
- Only show the flow JSON if the user explicitly asks to see it.

Running guidance:
- Before running a flow, call get_agent_flow and inspect initState, node requires, and promptTemplate placeholders.
- Build the arguments object to supply only the required keys the flow expects.
- If required inputs are missing or unclear, ask the user for the minimal missing values before calling run_agent_flow.

Self-validation:
- Before producing final JSON, verify the required keys checklist, toolSpecId references, and branch statuses.
- Confirm every referenced function exists in toolSpecs and required parameters are present in the promptTemplate.
- Confirm each node output is either used by a downstream requires or is part of the final outputs.
";

        public AgentFlowExpertToolsBuilder(IFunctionDefinitionRegistry functionDefinitionRegistry)
        {
            _tools = new List<ToolDefinition>
            {
                new ToolDefinition { Function = AgentFlowTools.BuildAddAgentFlowFunction(), Type = "function" },
                new ToolDefinition { Function = AgentFlowTools.BuildGetAgentFlowFunction(), Type = "function" },
                new ToolDefinition { Function = AgentFlowTools.BuildListAgentFlowsFunction(), Type = "function" },
                new ToolDefinition { Function = AgentFlowTools.BuildDeleteAgentFlowFunction(), Type = "function" },
                new ToolDefinition { Function = AgentFlowTools.BuildRunAgentFlowFunction(), Type = "function" }
            };
            _prompt = BuildPrompt(functionDefinitionRegistry);
        }

        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            var content = _prompt.Replace("{time}", currentTime);
            return new List<ChatMessage>
            {
                new ChatMessage
                {
                    Role = "system",
                    Content = content
                }
            };
        }

        private static string BuildPrompt(IFunctionDefinitionRegistry functionDefinitionRegistry)
        {
            var functionsJson = functionDefinitionRegistry.GetFilteredFunctionCatalogJson(pretty: true);
            var sb = new StringBuilder();
            sb.AppendLine("### Available functions");
            sb.AppendLine("```json");
            sb.AppendLine(functionsJson);
            sb.AppendLine("```");
            sb.AppendLine();
            sb.Append(PromptHeader);
            sb.AppendLine();
            sb.Append(PromptRules);
            return sb.ToString();
        }
    }
}

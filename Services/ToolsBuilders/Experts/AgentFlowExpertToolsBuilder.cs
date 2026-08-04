using NetworkMonitor.Objects.ServiceMessage;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using System.Collections.Generic;
using System;
using System.IO;
using System.Text;

namespace NetworkMonitor.LLM.Services
{
    public class AgentFlowExpertToolsBuilder : ToolsBuilderBase
    {
        private readonly string _prompt;
        private static readonly Lazy<string> AgentGraphSchema = new(LoadAgentGraphSchema);
        private const string PromptInstructions = @"
When creating or editing an agent flow follow these rules.

1. TOP-LEVEL RULES
1.1 The root must include: ""version"": 1, ""startNode"", ""nodes"", ""toolSpecs"".
1.2 Choose a unique startNode id that appears in nodes.
1.3 initState is optional. Add {""RetryLimit"": 2} when you want automatic retries.
1.4 Every toolSpecId referenced by a node must have a matching entry in toolSpecs.
1.5 All strings are plain UTF-8. Never emit markdown fences, back-ticks, or comments.
1.6 Declare each value that the caller must supply to run_agent_flow in runtimeInputs. A runtimeInputs key must not also appear in initState; use initState only for flow-provided defaults. Runtime arguments are checked before the flow starts.

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

3.1 PENETRATION FLOW REQUIREMENTS
- Put knowledge-base reconnaissance immediately after service enumeration and before Metasploit module selection.
- The knowledge-base node must expose execute_query_penetration, call it with query_text and vector_search_mode, and save its result as an output for later nodes.
- Later module-selection and module-information nodes must require and use that saved guidance.
- Keep reconnaissance flows non-executing unless the user explicitly asks for a separate execution phase.

4. PROMPT AND PLACEHOLDER RULES
4.1 Use placeholders exactly as {{Key}}, {{Key|Fallback}}, or {{Prompts.Method(args)}}.
4.2 Prompt text must be self-contained; do not mention schemas or internal code.

5. VALIDATION AND STATE ALIGNMENT
5.1 Every key in outputs is validated and stored in state if present.
5.2 Later nodes must reference the stored outputs in their required fields.
5.3 Missing or mis-named keys cause runtime failure.

6. FINISH CRITERIA
- When composing a flow document for add_agent_flow, its json argument must contain exactly one JSON object conforming to the schema.
- The flow JSON has no trailing commas, extra keys, wrapper arrays, or explanatory text.
- Do not return the flow JSON to the user unless they explicitly ask to see it.

7. EXECUTION AND STORAGE
- After you create a flow JSON, you MUST call add_agent_flow to save it.
- If the user asks to list, get, or delete flows, call list_agent_flows/get_agent_flow/delete_agent_flow directly and return the tool result. Do NOT create a flow JSON for those requests.
- For run requests, call run_agent_flow with the flow name and required arguments, then return the tool output.

8. HARD REQUIREMENTS CHECKLIST
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
- Before running a flow, call get_agent_flow and inspect runtimeInputs, initState, node requires, and promptTemplate placeholders.
- Build the arguments object to supply only the required keys the flow expects.
- If required inputs are missing or unclear, ask the user for the minimal missing values before calling run_agent_flow.

Self-validation:
- Before producing final JSON, verify the required keys checklist, toolSpecId references, and branch statuses.
- Confirm every referenced function exists in toolSpecs and required parameters are present in the promptTemplate.
- Confirm each node output is either used by a downstream requires or is part of the final outputs.

Template (minimal scan flow):
{""version"":1,""startNode"":""get_targets"",""initState"":{""agent_location"":""Scanner - EU""},""nodes"":[{""id"":""get_targets"",""type"":""template-llm"",""toolSpecId"":""monitor-tool"",""promptTemplate"":""Call get_host_list to retrieve enabled monitored hosts. Output targets as a space-separated string in key 'targets'."",""outputs"":[""targets""],""next"":""run_nmap""},{""id"":""run_nmap"",""type"":""template-llm"",""toolSpecId"":""monitor-tool"",""promptTemplate"":""Use scan_options '-sT -sV --open --top-ports 100 --max-retries 1'. Call run_nmap with target={{targets}}, scan_options as strings, and agent_location={{agent_location}}. Save raw output in 'nmap_results'."",""requires"":[""targets"",""agent_location""],""outputs"":[""nmap_results""],""next"":null}],""toolSpecs"":[{""id"":""monitor-tool"",""systemPrompt"":""Use get_host_list and run_nmap only."",""functions"":[""get_host_list"",""run_nmap""]}]}
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
            content = ExpertPromptComposer.Compose(content, currentTime, "agentflow");
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
            sb.AppendLine("### Agenic-Flow Graph JSON Schema");
            sb.AppendLine("```json");
            sb.AppendLine(AgentGraphSchema.Value);
            sb.AppendLine("```");
            sb.Append(PromptInstructions);
            sb.AppendLine();
            sb.Append(PromptRules);
            return sb.ToString();
        }

        private static string LoadAgentGraphSchema()
        {
            var schemaPath = Path.Combine(AppContext.BaseDirectory, "Schemas", "agent_schema.json");
            if (!File.Exists(schemaPath))
            {
                throw new FileNotFoundException("Agent graph schema was not deployed with NetworkMonitorLLM.", schemaPath);
            }

            return File.ReadAllText(schemaPath).Trim();
        }
    }
}

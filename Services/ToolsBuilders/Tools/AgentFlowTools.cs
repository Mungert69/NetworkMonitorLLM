using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Factory;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public static class AgentFlowTools
{
    public static FunctionDefinition BuildAddAgentFlowFunction()
    {
        return new FunctionDefinition
        {
            Name = "add_agent_flow",
            Description = "Add or update an agent flow JSON file for the current user. The flow is stored per user and can be run later by name.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["flow_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The flow name (used as the filename key)."
                    },
                    ["json"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent flow JSON content."
                    },
                    ["overwrite"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Set true to overwrite an existing flow with the same name."
                    }
                },
                Required = new List<string> { "flow_name", "json" }
            }
        };
    }

    public static FunctionDefinition BuildGetAgentFlowFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_agent_flow",
            Description = "Get a previously saved agent flow JSON for the current user.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["flow_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The flow name to retrieve."
                    }
                },
                Required = new List<string> { "flow_name" }
            }
        };
    }

    public static FunctionDefinition BuildListAgentFlowsFunction()
    {
        return new FunctionDefinition
        {
            Name = "list_agent_flows",
            Description = "List all agent flows saved for the current user.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>()
            }
        };
    }

    public static FunctionDefinition BuildDeleteAgentFlowFunction()
    {
        return new FunctionDefinition
        {
            Name = "delete_agent_flow",
            Description = "Delete an agent flow JSON for the current user.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["flow_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The flow name to delete."
                    }
                },
                Required = new List<string> { "flow_name" }
            }
        };
    }

    public static FunctionDefinition BuildRunAgentFlowFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_agent_flow",
            Description = "Run a saved agent flow by name with optional arguments.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["flow_name"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The flow name to run."
                    },
                    ["arguments"] = new PropertyDefinition
                    {
                        Type = "object",
                        Description = "Optional key/value arguments passed into the flow. Include every key declared by the flow's runtimeInputs."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional agent location override for the flow."
                    }
                },
                Required = new List<string> { "flow_name" }
            }
        };
    }
}

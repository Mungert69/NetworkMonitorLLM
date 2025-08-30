using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Factory;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;

namespace NetworkMonitor.LLM.Services;

public class CmdProcessorTools
{
    public static FunctionDefinition BuildListFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_cmd_processor_list",
            Description = "Get a list of command processors available for a given agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Get a list of cmd processors from an agent with this location."
                    }
                },
                Required = new List<string> { "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildHelpFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_cmd_processor_help",
            Description = "Get help information for a specific cmd processor type on a given agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["cmd_processor_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the cmd processor to get help for. Case sensitive."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location where the cmd processor resides."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Number of lines to return. Set to -1 to use the default value. Increase this if you need more data returned by the command. Be careful with using larger numbers as a lot of data can be returned. Note that HTML output will be parsed into text with newlines. To override this behavior and return all output in an unprocessed format, set number_lines to -2."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The page of lines to return. Use to paginate through many lines of data. Start at page 1"
                    }
                },
                Required = new List<string> { "cmd_processor_type", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildSourceCodeFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_cmd_processor_source_code",
            Description = "Get the source code for a specific cmd processor type on a given agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["cmd_processor_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the cmd processor to get the source code for. Case sensitive."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location where the cmd processor resides."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Number of lines to return. Set to -1 to use the default value. Increase this if you need more data returned by the command. Be careful with using larger numbers as a lot of data can be returned."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The page of lines to return. Use to paginate through many lines of data. Start at page 1"
                    }
                },
                Required = new List<string> { "cmd_processor_type", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildAddFunction()
    {
        return new FunctionDefinition
        {
            Name = "add_cmd_processor",
            Description = "Add or update a cmd processor with provided source code to an agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["cmd_processor_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the cmd processor to add. Use this name when referencing the processor later."
                    },
                    ["source_code"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The .NET source code implementing the cmd processor. Must extend CmdProcessor base class. Make sure to include all using statements, methods and supporting classes."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The location of the agent to which this cmd processor will be added."
                    }
                },
                Required = new List<string> { "cmd_processor_type", "source_code", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildRunFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_cmd_processor",
            Description = "Run a previously added cmd processor on a given agent. After running the cmd processor give the user the full output, do not summerize it",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["cmd_processor_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the cmd processor to run. Case sensitive."
                    },
                    ["arguments"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The arguments to pass to the cmd processor. Use get_cmd_processor_help for details on usage."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location where the cmd processor is to be run."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Number of lines to return. Set to -1 to use the default value. Increase this if you need more data returned by the command. Be careful with using larger numbers as a lot of data can be returned."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "The page of lines to return. Use to paginate through many lines of data. Start at page 1"
                    }
                },
                Required = new List<string> { "cmd_processor_type", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildDeleteFunction()
    {
        return new FunctionDefinition
        {
            Name = "delete_cmd_processor",
            Description = "Delete a cmd processor from an agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["cmd_processor_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the cmd processor to delete. Case sensitive."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location from which to delete the cmd processor."
                    }
                },
                Required = new List<string> { "cmd_processor_type", "agent_location" }
            }
        };
    }
}

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

public class ConnectTools
{
    public static FunctionDefinition BuildListFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_connect_list",
            Description = "Get a list of connect types available for a given agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Get a list of connects from an agent with this location."
                    }
                },
                Required = new List<string> { "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildSourceCodeFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_connect_source_code",
            Description = "Get the source code for a specific connect type on a given agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["connect_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the connect to get the source code for. Case sensitive."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location where the connect resides."
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
                Required = new List<string> { "connect_type", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildAddFunction()
    {
        return new FunctionDefinition
        {
            Name = "add_connect",
            Description = "Add or update a connect type with provided source code on an agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["connect_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the connect to add. Use this name when referencing the connect later."
                    },
                    ["source_code"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The .NET source code implementing the connect. Must be a {ConnectType}Connect class. Make sure to include all using statements, methods and supporting classes."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The location of the agent to which this connect will be added."
                    }
                },
                Required = new List<string> { "connect_type", "source_code", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildDeleteFunction()
    {
        return new FunctionDefinition
        {
            Name = "delete_connect",
            Description = "Delete a connect type from an agent.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["connect_type"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The name of the connect to delete. Case sensitive."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location from which to delete the connect."
                    }
                },
                Required = new List<string> { "connect_type", "agent_location" }
            }
        };
    }
}

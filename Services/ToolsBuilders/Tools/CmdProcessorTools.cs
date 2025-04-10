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

public class CmdProcessorTools{

     public static FunctionDefinition BuildListFunction()
    {
        return new  FunctionDefinitionBuilder("get_cmd_processor_list", "Get a list of command processors available for a given agent.")
                .AddParameter("agent_location", PropertyDefinition.DefineString("Get a list of cmd processors from an agent with this location."))
                .Validate()
                .Build();
    }
     public static FunctionDefinition BuildHelpFunction()
    {
        return new FunctionDefinitionBuilder("get_cmd_processor_help", "Get help information for a specific cmd processor type on a given agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to get help for. Case sensitive."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location where the cmd processor resides."))
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Set to -1 to use the default value. Increase this if you need more data returned by the command. Be careful with using larger numbers as a lot of data can be returned. Note that HTML output will be parsed into text with newlines. To override this behavior and return all output in an unprocessed format, set number_lines to -2."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data. Start at page 1"))
                .Validate()
                .Build();
    }
     public static FunctionDefinition BuildSourceCodeFunction()
    {
        return new FunctionDefinitionBuilder("get_cmd_processor_source_code", "Get the source code for a specific cmd processor type on a given agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to get the source code for. Case sensitive."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location where the cmd processor resides."))
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Set to -1 to use the default value. Increase this if you need more data returned by the command. Be careful with using larger numbers as a lot of data can be returned."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data. Start at page 1"))
                .Validate()
                .Build();
    }
     public static FunctionDefinition BuildAddFunction()
    {
        return new FunctionDefinitionBuilder("add_cmd_processor", "Add or update a cmd processor with provided source code to an agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to add. Use this name when referencing the processor later."))
                .AddParameter("source_code", PropertyDefinition.DefineString("The .NET source code implementing the cmd processor. Must extend CmdProcessor base class. Make sure to include all using statements, methods and supporting classes."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent to which this cmd processor will be added."))
                .Validate()
                .Build();

    }
     public static FunctionDefinition BuildRunFunction()
    {
        return new FunctionDefinitionBuilder("run_cmd_processor", "Run a previously added cmd processor on a given agent. After running the cmd processor give the user the full output, do not summerize it")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to run. Case sensitive."))
                .AddParameter("arguments", PropertyDefinition.DefineString("The arguments to pass to the cmd processor. Use get_cmd_processor_help for details on usage."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location where the cmd processor is to be run."))
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Set to -1 to use the default value. Increase this if you need more data returned by the command. Be careful with using larger numbers as a lot of data can be returned."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data. Start at page 1"))

                .Validate()
                .Build();
    }
     public static FunctionDefinition BuildDeleteFunction()
    {
        return new FunctionDefinitionBuilder("delete_cmd_processor", "Delete a cmd processor from an agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to delete. Case sensitive."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location from which to delete the cmd processor."))
                .Validate()
                .Build();
    }
}
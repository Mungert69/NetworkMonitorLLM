using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using OpenAI;
using OpenAI.Builders;
using OpenAI.Managers;
using OpenAI.ObjectModels;
using OpenAI.ObjectModels.RequestModels;
using OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;
using System.Threading.Tasks;
using System.IO;

namespace NetworkMonitor.LLM.Services
{
    public class CmdProcessorToolsBuilder : IToolsBuilder
    {
        private readonly FunctionDefinition fn_get_cmd_processor_list;
        private readonly FunctionDefinition fn_get_cmd_processor_help;
        private readonly FunctionDefinition fn_add_cmd_processor;
        private readonly FunctionDefinition fn_run_cmd_processor;
        private readonly FunctionDefinition fn_delete_cmd_processor;
        private readonly FunctionDefinition fn_get_cmd_processor_source_code;

        private readonly List<ToolDefinition> _tools;

        public List<ToolDefinition> Tools => _tools;

        public CmdProcessorToolsBuilder(UserInfo userInfo)
        {
            // Define get_cmd_processor_list
            fn_get_cmd_processor_list = new FunctionDefinitionBuilder("get_cmd_processor_list", "Get a list of command processors available for a given agent.")
                .AddParameter("agent_location", PropertyDefinition.DefineString("Get a list of cmd processors from an agent with this location."))
                .Validate()
                .Build();

            // Define get_cmd_processor_help
            fn_get_cmd_processor_help = new FunctionDefinitionBuilder("get_cmd_processor_help", "Get help information for a specific cmd processor type on a given agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to get help for. Case sensitive."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location where the cmd processor resides."))
                .Validate()
                .Build();
            
             // Define get_cmd_processor_source_code
            fn_get_cmd_processor_source_code = new FunctionDefinitionBuilder("get_cmd_processor_source_code", "Get the source code for a specific cmd processor type on a given agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to get the source code for. Case sensitive."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location where the cmd processor resides."))
                .Validate()
                .Build();

                

            // Define add_cmd_processor
            fn_add_cmd_processor = new FunctionDefinitionBuilder("add_cmd_processor", "Add or update a cmd processor with provided source code to an agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to add. Use this name when referencing the processor later."))
                .AddParameter("source_code", PropertyDefinition.DefineString("The .NET source code implementing the cmd processor. Must extend CmdProcessor base class. Make sure to include all using statements, methods and supporting classes. ENSURE that this fields value is accurately formatted and escaped according to JSON standards."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent to which this cmd processor will be added."))
                .Validate()
                .Build();

            // Define run_cmd_processor
            fn_run_cmd_processor = new FunctionDefinitionBuilder("run_cmd_processor", "Run a previously added cmd processor on a given agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to run. Case sensitive."))
                .AddParameter("arguments", PropertyDefinition.DefineString("The arguments to pass to the cmd processor. Use get_cmd_processor_help for details on usage."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location where the cmd processor is to be run."))
                .Validate()
                .Build();

            // Define delete_cmd_processor
            fn_delete_cmd_processor = new FunctionDefinitionBuilder("delete_cmd_processor", "Delete a cmd processor from an agent.")
                .AddParameter("cmd_processor_type", PropertyDefinition.DefineString("The name of the cmd processor to delete. Case sensitive."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location from which to delete the cmd processor."))
                .Validate()
                .Build();

            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_get_cmd_processor_list, Type = "function" },
                new ToolDefinition() { Function = fn_get_cmd_processor_help, Type = "function" },
                new ToolDefinition() { Function = fn_get_cmd_processor_source_code, Type = "function" },
                new ToolDefinition() { Function = fn_add_cmd_processor, Type = "function" },
                new ToolDefinition() { Function = fn_run_cmd_processor, Type = "function" },
                new ToolDefinition() { Function = fn_delete_cmd_processor, Type = "function" }
            };
        }

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
        {
            // Construct the system content from the original prompt instructions
            string contentPart1 =
@"You are an AI-powered assistant that creates and interacts with Command Processors. 
A Command Processor is a .NET class that runs on an agent and can be invoked via defined functions.

**.NET Source Code in add_cmd_processor**:
When adding a cmd processor, supply its source code in the 'source_code' parameter. The code must inherit from:

namespace NetworkMonitor.Connection {
    public abstract class CmdProcessor
    {
        protected ILogger _logger;
        protected ILocalCmdProcessorStates _cmdProcessorStates;
        protected IRabbitRepo _rabbitRepo;
        protected NetConnectConfig _netConfig;
        protected string _rootFolder; // the folder to read and write files to.

        public CmdProcessor(ILogger logger, ILocalCmdProcessorStates cmdProcessorStates, IRabbitRepo rabbitRepo, NetConnectConfig netConfig)
        {
            _logger = logger;
            _cmdProcessorStates = cmdProcessorStates;
            _rabbitRepo = rabbitRepo;
            _netConfig = netConfig;
        }

        public abstract Task<ResultObj> RunCommand(string arguments, CancellationToken cancellationToken, ProcessorScanDataObj? processorScanDataObj = null);
        public abstract string GetCommandHelp();
    }
}
";
            string contentPart2;
            string tempContent;
            try
            {
                tempContent = File.ReadAllText(Path.Combine("Examples","Example.cs"));
                if (string.IsNullOrWhiteSpace(tempContent))
                {
                    contentPart2 = "";
                }
                else
                {
                    contentPart2 = "Here is an example implementation: " + tempContent;
                }
            }
            catch (Exception ex)
            {
                contentPart2 = "";
            }

            string contentPart3 = @"
    
To aid compilation make sure to include all of these using statements in any source code you produce:
using System; 
using System.Text; 
using System.Collections.Generic; 
using System.Diagnostics; 
using System.Threading.Tasks; 
using System.Text.RegularExpressions; 
using Microsoft.Extensions.Logging; 
using System.Linq;
using NetworkMonitor.Objects; 
using NetworkMonitor.Objects.Repository; 
using NetworkMonitor.Objects.ServiceMessage; 
using NetworkMonitor.Connection; 
using NetworkMonitor.Utils; 
using System.Xml.Linq; 
using System.IO;
using System.Threading; 
using System.Net; 

namespace NetworkMonitor.Connection {
 // The source code here ...
}

Important: Ensure that the source_code parameter is accurately formatted and escaped according to JSON standards.
Also make sure not to include word CmdProcessor in the cmd_processor_type. For example if you want to call the cmd processor HttpTest then cmd_processor_type is HttpTest and the class name is HttpTestCmdProcessor.
Use _rootFolder for file operations as this has read write access. Try and implement the CancellationToken cancellationToken to make sure the command can be cancelled.

If the user requests to add a cmd processor, produce a call to add_cmd_processor with the cmd_processor_type, the agent_location, and the .NET source code correctly escaped for json.

If the user wants to run, delete, or get help from a cmd processor, use the corresponding tools with the correct parameters.

The user can also request to see what cmd processors are currently available by calling get_cmd_processor_list with the agent location.

Your goal is to help the user set up and manage cmd processors on different agents as requested.";

            string content = contentPart1 + contentPart2 + contentPart3;
            if (serviceObj.IsUserLoggedIn)
                content += $" The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}.";
            else
                content += $" The user is not logged in, current time: {currentTime}. Prompt them if needed.";

            var chatMessage = new ChatMessage()
            {
                Role = "system",
                Content = content
            };

            return new List<ChatMessage> { chatMessage };
        }
    }
}

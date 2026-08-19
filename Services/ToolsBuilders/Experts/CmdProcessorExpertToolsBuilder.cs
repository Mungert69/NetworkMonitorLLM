using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;
using System.Threading.Tasks;
using System.IO;

namespace NetworkMonitor.LLM.Services
{
    public class CmdProcessorExpertToolsBuilder : ToolsBuilderBase
    {
        private readonly FunctionDefinition fn_get_cmd_processor_list;
        private readonly FunctionDefinition fn_get_cmd_processor_help;
        private readonly FunctionDefinition fn_add_cmd_processor;
        private readonly FunctionDefinition fn_run_cmd_processor;
        private readonly FunctionDefinition fn_delete_cmd_processor;
        private readonly FunctionDefinition fn_get_cmd_processor_source_code;


        public CmdProcessorExpertToolsBuilder()
        {

            fn_get_cmd_processor_list = CmdProcessorTools.BuildListFunction();
            fn_get_cmd_processor_help = CmdProcessorTools.BuildHelpFunction();
            fn_get_cmd_processor_source_code = CmdProcessorTools.BuildSourceCodeFunction();
            fn_add_cmd_processor = CmdProcessorTools.BuildAddFunction();
            fn_run_cmd_processor = CmdProcessorTools.BuildRunFunction();
            fn_delete_cmd_processor = CmdProcessorTools.BuildDeleteFunction();

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

        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            // Construct the system content from the original prompt instructions
            string overridePrompt = $@"You are an automated Cmd Processor manager opertating withn the Network Monitor Assistant. You creates, interacts and manage Command Processors. 
A Command Processor is a .NET class that runs on an agent and can be invoked via run_cmd_processor.
 {Prompts.CmdProcessorPrompt()}";

            string contentPart2 = @" If the user requests to add a cmd processor, call the function add_cmd_processor with parameters cmd_processor_type, the agent_location.

The user can also: delete a cmd processor (delete_cmd_processor), or get the help file for a cmd processor (get_cmd_processor_help), view the .net source code that the cmd processor runs (get_cmd_processor_source_code) and run a cmd processor (run_cmd_processor).

The user can also request to see what cmd processors are currently available by calling get_cmd_processor_list with the agent location.

You will not ask the user to supply the source code when adding or updating a cmd processor. When the user requests a new or updated cmd processor it is your job as the cmd processor expert to take the users request and convert that as best as you can, without question, to .net source code and then add the cmd processor.

Your overal goal is to help the user set up and manage cmd processors on the requested agents in a simple and helpful manor.";

            string content = overridePrompt + contentPart2;
            content += $" The current time is{currentTime}.";
            content = ExpertPromptComposer.Compose(content, currentTime, "cmdprocessor");
            var chatMessage = new ChatMessage()
            {
                Role = "system",
                Content = content
            };

            return new List<ChatMessage> { chatMessage };
        }
    }
}

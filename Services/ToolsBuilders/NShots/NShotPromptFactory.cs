using System;
using System.Collections.Generic;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;

namespace NetworkMonitor.LLM.Services
{
    public static class NShotPromptFactory
    {
        // Factory method to return the appropriate prompt by name
        public static List<ChatMessage> GetPrompt(string name, bool isXml = false)
        {
            if (isXml) name += "xml";
            switch (name.ToLower())
            {
                case "cmdprocessorxml":
                    return GetCmdProcessorXml();
                // Add more cases here for additional prompt types
                // case "anotherprompt":
                //     return GetAnotherPrompt();
                default:
                    return new List<ChatMessage>();
            }
        }

        /// <summary>
        /// A helper method that creates a triple of messages in the conversation:
        /// 1) A user message.
        /// 2) An assistant message containing a function call.
        /// 3) A tool (function response) message.
        /// </summary>
        /// <param name="messages">The list of messages to add to.</param>
        /// <param name="userPrompt">The user question or request.</param>
        /// <param name="assistantPrompt">The assistant message, which includes the function_call text in plain text.</param>
        /// <param name="toolResponse">The content returned by the tool in JSON or some other format.</param>
        /// <param name="functionName">The name of the function in the ToolCall object.</param>
        /// <param name="functionArguments">Any string representing the function's arguments field.</param>
        /// <param name="toolCallType">"function" by default, can be changed if needed.</param>
        private static void AddAssistantMessageWithToolCall(
            List<ChatMessage> messages,
            string userPrompt,
            string assistantPrompt,
            string toolResponse,
            string functionName,
            string functionArguments = "",
            string toolCallType = "function")
        {
            // 1) Add user message
            messages.Add(ChatMessage.FromUser(userPrompt));

            // 2) Create assistant message with a ToolCall
            var toolCallId = "call_" + StringUtils.GetNanoid();
            var assistantMessage = ChatMessage.FromAssistant(assistantPrompt);

            assistantMessage.ToolCalls = new List<ToolCall>
            {
                new ToolCall
                {
                    Type = toolCallType,
                    Id = toolCallId,
                    FunctionCall = new FunctionCall
                    {
                        Name = functionName,
                        Arguments = functionArguments
                    }
                }
            };

            messages.Add(assistantMessage);

            // 3) Add the tool (function response)
            messages.Add(ChatMessage.FromTool(toolResponse,toolCallId));
        }

        private static List<ChatMessage> GetCmdProcessorXml()
        {
            var messages = new List<ChatMessage>();

            // --------------------------------------------------
            // 1ST GROUP: user -> assistant (with function_call) -> tool
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                // 1) userPrompt
                "Please can you create a cmd processor to run the ls command on my agent",
                // 2) assistantPrompt (includes the <function_call>)
@"I will create a cmd processor that will run the ls command
<function_call name=""add_cmd_processor"">
    <parameters>
        <cmd_processor_type>List</cmd_processor_type>
        <source_code>
        <![CDATA[
using System; // Required base functionality
using System.Text; // For StringBuilder
using System.Collections.Generic; // For collections
using System.Diagnostics; // For Process execution
using System.Threading.Tasks; // For async/await
using System.Text.RegularExpressions; // For regex operations
using Microsoft.Extensions.Logging; // For logging
using System.Linq; // For LINQ operations
using NetworkMonitor.Objects; // For application-specific objects
using NetworkMonitor.Objects.Repository; // For repository handling
using NetworkMonitor.Objects.ServiceMessage; // For service messaging
using NetworkMonitor.Connection; // For connection handling
using NetworkMonitor.Utils; // For utility methods
using System.Xml.Linq; // For XML handling
using System.IO; // For file operations
using System.Threading; // For CancellationToken
using System.Net; // For Network operations

namespace NetworkMonitor.Connection
{
    public class ListCmdProcessor : CmdProcessor
    {
        public ListCmdProcessor(ILogger logger, ILocalCmdProcessorStates cmdProcessorStates, IRabbitRepo rabbitRepo, NetConnectConfig netConfig)
            : base(logger, cmdProcessorStates, rabbitRepo, netConfig) {}

        public override async Task<ResultObj> RunCommand(string arguments, CancellationToken cancellationToken, ProcessorScanDataObj? processorScanDataObj = null)
        {
            var result = new ResultObj();
            string output = """";
            try
            {
                // Check if the command is available
                if (!_cmdProcessorStates.IsCmdAvailable)
                {
                    var warningMessage = $""{_cmdProcessorStates.CmdDisplayName} is not available on this agent."";
                    _logger.LogWarning(warningMessage);
                    output = $""{_cmdProcessorStates.CmdDisplayName} is not available.\n"";
                    result.Message = output;
                    result.Success = false;
                    return result;
                }

                // Execute the 'ls' command
                using (var process = new Process())
                {
                    process.StartInfo.FileName = ""ls"";
                    process.StartInfo.Arguments = arguments;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.WorkingDirectory = _netConfig.CommandPath;

                    var outputBuilder = new StringBuilder();
                    process.OutputDataReceived += (sender, e) => 
                    { 
                        if (e.Data != null) outputBuilder.AppendLine(e.Data); 
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    await process.WaitForExitAsync(cancellationToken);

                    output = outputBuilder.ToString();
                    result.Success = true;
                    result.Message = output;
                }
            }
            catch (Exception e)
            {
                var errorMessage = $""Error in RunCommand: {e.Message}"";
                _logger.LogError(errorMessage);
                result.Success = false;
                result.Message = errorMessage;
            }
            return result;
        }

        public override string GetCommandHelp()
        {
            return @""This command runs the Unix 'ls' command to list directory contents..."";
        }
    }
}
        ]]>
        </source_code>
        <agent_location>Scanner - EU</agent_location>
    </parameters>
</function_call>",
                // 3) toolResponse
@"{{""message"" : ""Success: added List cmd processor"", ""success"" : true, ""agent_location"" : ""London - UK"" }}",
                // functionName
                "add_cmd_processor"
            );

            // 4) Final Assistant message after the triple
            messages.Add(ChatMessage.FromAssistant(
                "I have added a cmd processor List. It is ready for use on agent London - UK"
            ));


            // --------------------------------------------------
            // 2ND GROUP: user -> assistant (with function_call) -> tool
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Can you run ls on agent London - UK",
@"Yes I will run ls on agent London - UK
<function_call name=""run_cmd_processor"">
    <parameters>
        <cmd_processor_type>List</cmd_processor_type>
        <arguments>-l</arguments>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
@"{{""message"" : "" ls command output nmap meta openssl busybox"", ""success"" : true, ""agent_location"" : ""London - UK"" }}",
                "run_cmd_processor"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The list command that was run on agent London - UK shows four files: nmap, meta, openssl, and busybox."
            ));


            // --------------------------------------------------
            // 3RD GROUP: user -> assistant (with function_call) -> tool
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Can you create a commmand to test ftp sites. I would like it to run on Scanner - US",
@"I will create a FTPConnectionTester on agent Scanner - US
<function_call name=""add_cmd_processor"">
    <parameters>
        <cmd_processor_type>FTPConnectionTester</cmd_processor_type>
        <source_code>
        <![CDATA[
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

namespace NetworkMonitor.Connection
{
    public class FTPConnectionTesterCmdProcessor : CmdProcessor
    {
        public FTPConnectionTesterCmdProcessor(ILogger logger, ILocalCmdProcessorStates cmdProcessorStates, IRabbitRepo rabbitRepo, NetConnectConfig netConfig)
            : base(logger, cmdProcessorStates, rabbitRepo, netConfig) { }

        public override async Task<ResultObj> RunCommand(string arguments, CancellationToken cancellationToken, ProcessorScanDataObj? processorScanDataObj = null)
        {
            var result = new ResultObj();
            try
            {
                // Implementation for checking FTP connections...
                result.Success = true;
                result.Message = ""FTP connection successful."";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $""Error testing FTP connection: {ex.Message}"";
            }
            return result;
        }

        public override string GetCommandHelp()
        {
            return @""This command tests an FTP connection by attempting to list the directory contents..."";
        }
    }
}
        ]]>
        </source_code>
        <agent_location>Scanner - US</agent_location>
    </parameters>
</function_call>",
@"{{""message"" : ""Success: added FtpConnectionTester cmd processor"", ""success"" : true, ""agent_location"" : ""Scanner - US"" }}","add_cmd_processor");

            messages.Add(ChatMessage.FromAssistant(
                "I have created a FTPConnectionTester cmd processor and it is ready for use on agent Scanner - US"
            ));


            // --------------------------------------------------
            // 4TH GROUP: user -> assistant (with function_call) -> tool
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Can you check if ftp ftpsite.com is working I use username test password test123",
@"I will check this site
<function_call name=""run_cmd_processor"">
    <parameters>
        <cmd_processor_type>FTPConnectionTester</cmd_processor_type>
        <arguments>--username test --password test123 --host ftpsite.com</arguments>
        <agent_location>Scanner - US</agent_location>
    </parameters>
</function_call>",
@"{{""message"": ""Success: ftpsite.com connection success"", ""success"": true, ""agent_location"": ""Scanner - US""}}",
                "run_cmd_processor"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The FTP connection to ftpsite.com was successful."
            ));

             // --------------------------------------------------
            // 5TH GROUP: user -> assistant (with function_call) -> tool
            // (Delete the List CmdProcessor)
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                // userPrompt
                "Please delete the List cmd processor.",
                // assistantPrompt
                @"Ok, removing the List cmd processor now.\n<function_call name=""delete_cmd_processor"">\n    <parameters>\n        <cmd_processor_type>List</cmd_processor_type>\n        <agent_location>London - UK</agent_location>\n    </parameters>\n</function_call>",
                // toolResponse
                @"{{""message"" : ""Success: deleted List cmd processor"", ""success"" : true, ""agent_location"" : ""London - UK"" }}",
                // functionName
                "delete_cmd_processor"
            );

            // final assistant message after the triple
            messages.Add(ChatMessage.FromAssistant(
                "The List cmd processor has been removed from the agent."
            ));

            // --------------------------------------------------
            // 6TH GROUP: user -> assistant (with function_call) -> tool
            // (Delete the FTPConnectionTester CmdProcessor)
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                // userPrompt
                "Also, please delete the FTPConnectionTester cmd processor.",
                // assistantPrompt
                @"Sure, removing the FTPConnectionTester cmd processor now.\n<function_call name=""delete_cmd_processor"">\n    <parameters>\n        <cmd_processor_type>FTPConnectionTester</cmd_processor_type>\n        <agent_location>Scanner - US</agent_location>\n    </parameters>\n</function_call>",
                // toolResponse
                @"{{""message"" : ""Success: deleted FTPConnectionTester cmd processor"", ""success"" : true, ""agent_location"" : ""Scanner - US"" }}",
                // functionName
                "delete_cmd_processor"
            );

            // final assistant message after the triple
            messages.Add(ChatMessage.FromAssistant(
                "The FTPConnectionTester cmd processor has been removed as well."
            ));


            return messages;
        }

        // Example placeholder for additional prompts
        private static List<ChatMessage> GetAnotherPrompt()
        {
            var messages = new List<ChatMessage>();
            messages.Add(ChatMessage.FromUser("Example user message for AnotherPrompt"));
            messages.Add(ChatMessage.FromAssistant("Example assistant response for AnotherPrompt"));
            return messages;
        }
    }
}

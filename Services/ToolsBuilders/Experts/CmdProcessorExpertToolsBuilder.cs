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


        public CmdProcessorExpertToolsBuilder(UserInfo userInfo)
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
            string contentPart1 =
@"You are an automated Cmd Processor manager opertating withn the Network Monitor Assistant. You creates, interacts and manage Command Processors. 
A Command Processor is a .NET class that runs on an agent and can be invoked via run_cmd_processor.

**.NET Source Code in add_cmd_processor**:
When adding a cmd processor, supply its source code in the 'source_code' parameter. The code must inherit from the base class CmdProcessor
For reference and outline of the CmdProcesor Base class is given below :

namespace NetworkMonitor.Connection
{
    public interface ICmdProcessor : IDisposable
    {
         Task<ResultObj> RunCommand(string arguments, CancellationToken cancellationToken, ProcessorScanDataObj? processorScanDataObj = null);
          string GetCommandHelp();
    }
    public abstract class CmdProcessor : ICmdProcessor
    {
        protected readonly ILogger _logger;
        protected readonly ILocalCmdProcessorStates _cmdProcessorStates;
        protected readonly IRabbitRepo _rabbitRepo;
        protected readonly NetConnectConfig _netConfig;
        protected string _rootFolder; // the folder to read and write files to.
        protected CancellationTokenSource _cancellationTokenSource; // the cmd processor is cancelled using this.
        protected string _frontendUrl = AppConstants.FrontendUrl;
     

        public bool UseDefaultEndpoint { get => _cmdProcessorStates.UseDefaultEndpointType; set => _cmdProcessorStates.UseDefaultEndpointType = value; }
#pragma warning disable CS8618
        public CmdProcessor(ILogger logger, ILocalCmdProcessorStates cmdProcessorStates, IRabbitRepo rabbitRepo, NetConnectConfig netConfig)
        {
            _logger = logger;
            _cmdProcessorStates = cmdProcessorStates;
            _rabbitRepo = rabbitRepo;
            _netConfig = netConfig;
            _rootFolder = netConfig.CommandPath;  // use _rootFolder to access the agents file system
        }

        // You will override this method with your implementation.
        public virtual async Task<ResultObj> RunCommand(string arguments, CancellationToken cancellationToken, ProcessorScanDataObj? processorScanDataObj = null)
        {
            var result = new ResultObj();
            string output = "";
            try
            {
               
                using (var process = new Process())
                {
                    process.StartInfo.FileName = _netConfig.CommandPath + _cmdProcessorStates.CmdName;
                    process.StartInfo.Arguments = arguments;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true; // Add this to capture standard error

                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.WorkingDirectory = _netConfig.CommandPath;

                    var outputBuilder = new StringBuilder();
                    var errorBuilder = new StringBuilder();

                    process.OutputDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                        {
                            outputBuilder.AppendLine(e.Data);
                        }
                    };

                    process.ErrorDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                        {
                            errorBuilder.AppendLine(e.Data);
                        }
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    // Register a callback to kill the process if cancellation is requested
                    using (cancellationToken.Register(() =>
                    {
                        if (!process.HasExited)
                        {
                            _logger.LogInformation($""Cancellation requested, killing the {_cmdProcessorStates.CmdDisplayName} process..."");
                            process.Kill();
                        }
                    }))
                    {
                        // Wait for the process to exit or the cancellation token to be triggered
                        await process.WaitForExitAsync(cancellationToken);
                        cancellationToken.ThrowIfCancellationRequested(); // Check if cancelled before processing output

                        output = outputBuilder.ToString();
                        string errorOutput = errorBuilder.ToString();

                        if (!string.IsNullOrWhiteSpace(errorOutput) && processorScanDataObj != null)
                        {
                            output = $""RedirectStandardError : {errorOutput}. \n RedirectStandardOutput : {output}"";
                        }
                        result.Success = true;
                    }
                }
            }
            catch (Exception e)
            {
                _logger.LogError($""Error : running {_cmdProcessorStates.CmdName} command. Error was : {e.Message}"");
                output += $""Error : running {_cmdProcessorStates.CmdName} command. Error was : {e.Message}\n"";
                result.Success = false;
            }
            result.Message = output;
            return result;
        }

        // You can use this helper method in your cmd processor for argument parsing
        protected virtual Dictionary<string, string> ParseArguments(string arguments)
        {
            var args = new Dictionary<string, string>();
            var regex = new Regex(@""--(?<key>\w+)\s+(?<value>[^\s]+)"");
            var matches = regex.Matches(arguments);

            foreach (Match match in matches)
            {
                args[match.Groups[""key""].Value.ToLower()] = match.Groups[""value""].Value;
            }

            return args;
        }      
        public virtual string GetCommandHelp()
        {
            // override this method and provide the help as a returned string.
        }
   
    }

}

";
            
            string contentPart2 = @"Do not to include the word CmdProcessor in the cmd_processor_type. For example if you want to call the cmd processor HttpTest then cmd_processor_type is HttpTest and the class name is HttpTestCmdProcessor.
Use _rootFolder for file operations as this has read write access. Try and implement the CancellationToken cancellationToken to make sure the command can be cancelled.

If the user requests to add a cmd processor, call the function add_cmd_processor with parameters cmd_processor_type, the agent_location.

The user can also: delete a cmd processor (delete_cmd_processor), or get the help file for a cmd processor (get_cmd_processor_help), view the .net source code that the cmd processor runs (get_cmd_processor_source_code) and run a cmd processor (run_cmd_processor).

The user can also request to see what cmd processors are currently available by calling get_cmd_processor_list with the agent location.

You will not ask the user to supply the source code when adding or updating a cmd processor. When the user requests a new or updated cmd processor it is your job as the cmd processor expert to take the users request and convert that as best as you can, without question, to .net source code and then add the cmd processor.

Your overal goal is to help the user set up and manage cmd processors on the requested agents in a simple and helpful manor.";

            string content = contentPart1 + contentPart2;
            content += $" The current time is{currentTime}.";
            var chatMessage = new ChatMessage()
            {
                Role = "system",
                Content = content
            };

            return new List<ChatMessage> { chatMessage };
        }
    }
}

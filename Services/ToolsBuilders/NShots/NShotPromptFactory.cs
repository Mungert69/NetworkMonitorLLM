using System;
using System.Collections.Generic;
using System.Text.Json;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects.ServiceMessage;
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
        public static List<ChatMessage> GetPrompt(string name, bool isXml = false, params object[] args)
        {
            if (isXml) name += "xml";
            switch (name.ToLower())
            {
                case "cmdprocessorxml":
                    return GetCmdProcessorXml(args);
                case "connectxml":
                    return GetConnectXml(args);
                case "connect":
                    return GetConnectPrompt(args);
                case "agentflow":
                    return GetAgentFlowPrompt(args);
                case "user":
                    return GetUserSimulatorPrompt(args);
                default:
                    return GetDefaultPrompt(args);

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
            string? userPrompt,
            string assistantPrompt,
            string toolResponse,
            string functionName,
            string functionArguments = "",
            string toolCallType = "function")
        {
            // 1) Add user message
            if (userPrompt != null) messages.Add(ChatMessage.FromUser(userPrompt));

            // 2) Create assistant message with a ToolCall
            var toolCallId = StringUtils.NewToolCallId();
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
            messages.Add(ChatMessage.FromTool(toolResponse, toolCallId));
        }

        private static List<ChatMessage> GetCmdProcessorXml(params object[] args)
        {
            var messages = new List<ChatMessage>();

            // --------------------------------------------------
            // 1ST GROUP: user -> assistant (with function_call) -> tool
            // Add a schema-based ListCmdProcessor example
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                // 1) userPrompt
                "Please can you create a cmd processor to run an ls command on my agent using our standard schema-based arg parsing",
                // 2) assistantPrompt (with <function_call> and CDATA source code)
                @"<function_call name=""add_cmd_processor"">
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
// Add other using statements as needed

namespace NetworkMonitor.Connection
{
    /// <summary>
    /// Lists directory contents via 'ls', using schema-based CLI arg parsing.
    /// Args:
    ///   --path <string>            (default: '.')
    ///   --long                     (flag)
    ///   --all                      (flag)
    ///   --human                    (flag)
    ///   --recursive                (flag)
    ///   --timeout <int ms>         (default: 10000)
    /// </summary>
    public class ListCmdProcessor : CmdProcessor
    {
        private const int DefaultTimeoutMs = 10_000;
        private readonly List<ArgSpec> _schema;

        public ListCmdProcessor(ILogger logger, ILocalCmdProcessorStates cmdProcessorStates, IRabbitRepo rabbitRepo, NetConnectConfig netConfig)
            : base(logger, cmdProcessorStates, rabbitRepo, netConfig)
        {
            _schema = new()
            {
                new() { Key = ""path"",         Required = false, IsFlag = false, TypeHint = ""value"", DefaultValue = ""."", Help = ""Directory to list"" },
                new() { Key = ""long"",         Required = false, IsFlag = true,  DefaultValue = ""false"", Help = ""Long listing (-l)"" },
                new() { Key = ""all"",          Required = false, IsFlag = true,  DefaultValue = ""false"", Help = ""Include dot-files (-a)"" },
                new() { Key = ""human"",        Required = false, IsFlag = true,  DefaultValue = ""false"", Help = ""Human-readable sizes (-h)"" },
                new() { Key = ""recursive"",    Required = false, IsFlag = true,  DefaultValue = ""false"", Help = ""Recursive (-R)"" },
                new() { Key = ""timeout"",      Required = false, IsFlag = false, TypeHint = ""int"", DefaultValue = DefaultTimeoutMs.ToString(), Help = ""Process timeout (ms)"" },
            };
        }

        public override async Task<ResultObj> RunCommand(string arguments, CancellationToken cancellationToken, ProcessorScanDataObj? processorScanDataObj = null)
        {
            try
            {
                if (!_cmdProcessorStates.IsCmdAvailable)
                {
                    var m = $""{_cmdProcessorStates.CmdDisplayName} is not available on this agent."";
                    _logger.LogWarning(m);
                    return new ResultObj { Success = false, Message = m };
                }

                var parse = CliArgParser.Parse(arguments, _schema, allowUnknown: false, fillDefaults: true);
                if (!parse.Success)
                {
                    var err = CliArgParser.BuildErrorMessage(_cmdProcessorStates.CmdDisplayName, parse, _schema);
                    _logger.LogWarning(""Arguments not valid {args}. {msg}"", arguments, parse.Message);
                    return new ResultObj { Success = false, Message = err };
                }

                var path     = parse.GetString(""path"", ""."");
                var timeout  = parse.GetInt(""timeout"", DefaultTimeoutMs);
                var opts     = new StringBuilder();

                if (parse.GetBool(""long"", false))      opts.Append("" -l"");
                if (parse.GetBool(""all"", false))       opts.Append("" -a"");
                if (parse.GetBool(""human"", false))     opts.Append("" -h"");
                if (parse.GetBool(""recursive"", false)) opts.Append("" -R"");

                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = ""ls"",
                        Arguments = $""{opts} -- {path}"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        WorkingDirectory = _netConfig.CommandPath
                    }
                };

                var sb = new StringBuilder();
                process.OutputDataReceived += (_, e) => { if (!string.IsNullOrEmpty(e.Data)) sb.AppendLine(e.Data); };
                process.ErrorDataReceived  += (_, e) => { if (!string.IsNullOrEmpty(e.Data)) sb.AppendLine(e.Data); };

                process.Start();
                process.BeginOutputReadLine();
                using (cancellationToken.Register(() => { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch {} }))
                {
                    var exited = await Task.Run(() => process.WaitForExit(timeout), cancellationToken);
                    if (!exited) return new ResultObj { Success = false, Message = $""ls timed out after {timeout}ms"" };
                }

                return new ResultObj { Success = process.ExitCode == 0, Message = sb.ToString() };
            }
            catch (OperationCanceledException)
            {
                return new ResultObj { Success = false, Message = ""ls canceled or timed out.\n"" };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ""ListCmdProcessor error"");
                return new ResultObj { Success = false, Message = $""List error: {ex.Message}"" };
            }
        }

        public override string GetCommandHelp() => @""ListCmdProcessor
Lists directory contents using schema-based arguments.

Usage:
  --path <dir> [--long] [--all] [--human] [--recursive] [--timeout <ms>]

Examples:
  --path . --long --all
  --path /var/log --long --human
"";
    }
}
        ]]>
        </source_code>
        <agent_location>Scanner - EU</agent_location>
    </parameters>
</function_call>",
                // 3) toolResponse
                @"{""message"" : ""Success: added List cmd processor"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                // functionName
                "add_cmd_processor"
            );

            // Final assistant message after the triple
            messages.Add(ChatMessage.FromAssistant(
                "I have added a schema-based List cmd processor. It is ready for use on agent London - UK"
            ));

            // --------------------------------------------------
            // 2ND GROUP: user -> assistant (with function_call) -> tool
            // Run with schema-style flags
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Can you run List on agent London - UK to show /tmp with long + all?",
                @"<function_call name=""run_cmd_processor"">
    <parameters>
        <cmd_processor_type>List</cmd_processor_type>
        <arguments>--path /tmp --long --all</arguments>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""drwxr-xr-x  tmp stuff ..."", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "run_cmd_processor"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The listing for /tmp was retrieved successfully on agent London - UK."
            ));

            // --------------------------------------------------
            // 3RD GROUP: user -> assistant (with function_call) -> tool
            // Schema-based TcpPortCheck example (replacement for FTP example)
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Can you create a command to test TCP ports using our schema parsing on Scanner - US?",
                @"<function_call name=""add_cmd_processor"">
    <parameters>
        <cmd_processor_type>TcpPortCheck</cmd_processor_type>
        <source_code>
        <![CDATA[
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;

namespace NetworkMonitor.Connection
{
    /// <summary>
    /// Checks TCP connectivity to a host:port with schema-based argument parsing.
    /// Args:
    ///   --host <string>            (required)
    ///   --port <int>               (required)
    ///   --timeout_ms <int>         (default: 5000)
    ///   --attempts <int>           (default: 1)
    ///   --delay_ms <int>           (default: 0)
    /// </summary>
    public class TcpPortCheckCmdProcessor : CmdProcessor
    {
        private static readonly List<ArgSpec> _schema = new()
        {
            new() { Key = ""host"",       Required = true,  IsFlag = false, TypeHint = ""value"", Help = ""Target host or IP"" },
            new() { Key = ""port"",       Required = true,  IsFlag = false, TypeHint = ""int"",   Help = ""Target TCP port"" },
            new() { Key = ""timeout_ms"", Required = false, IsFlag = false, TypeHint = ""int"",   DefaultValue = ""5000"", Help = ""Per-attempt timeout (ms)"" },
            new() { Key = ""attempts"",   Required = false, IsFlag = false, TypeHint = ""int"",   DefaultValue = ""1"",    Help = ""Number of attempts"" },
            new() { Key = ""delay_ms"",   Required = false, IsFlag = false, TypeHint = ""int"",   DefaultValue = ""0"",    Help = ""Delay between attempts (ms)"" },
        };

        public TcpPortCheckCmdProcessor(
            ILogger logger,
            ILocalCmdProcessorStates cmdProcessorStates,
            IRabbitRepo rabbitRepo,
            NetConnectConfig netConfig)
            : base(logger, cmdProcessorStates, rabbitRepo, netConfig) { }

        public override async Task<ResultObj> RunCommand(
            string arguments,
            CancellationToken cancellationToken,
            ProcessorScanDataObj? processorScanDataObj = null)
        {
            try
            {
                if (!_cmdProcessorStates.IsCmdAvailable)
                {
                    var m = $""{_cmdProcessorStates.CmdDisplayName} is not available on this agent."";
                    _logger.LogWarning(m);
                    return new ResultObj { Success = false, Message = m };
                }

                var parse = CliArgParser.Parse(arguments, _schema, allowUnknown: false, fillDefaults: true);
                if (!parse.Success)
                {
                    var err = CliArgParser.BuildErrorMessage(_cmdProcessorStates.CmdDisplayName, parse, _schema);
                    _logger.LogWarning(""Arguments invalid: {msg}"", parse.Message);
                    return new ResultObj { Success = false, Message = err };
                }

                var host      = parse.GetString(""host"");
                var port      = parse.GetInt(""port"");
                var timeoutMs = parse.GetInt(""timeout_ms"", 5000);
                var attempts  = Math.Max(1, parse.GetInt(""attempts"", 1));
                var delayMs   = Math.Max(0, parse.GetInt(""delay_ms"", 0));

                var sb = new StringBuilder();
                bool anySuccess = false;

                for (int i = 1; i <= attempts; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var sw = Stopwatch.StartNew();
                    var ok = await TryConnect(host, port, timeoutMs, cancellationToken);
                    sw.Stop();

                    if (ok)
                    {
                        anySuccess = true;
                        sb.AppendLine($""Attempt {i}/{attempts}: CONNECTED in {sw.ElapsedMilliseconds} ms to {host}:{port}"");
                    }
                    else
                    {
                        var approx = Math.Min(sw.ElapsedMilliseconds, timeoutMs);
                        sb.AppendLine($""Attempt {i}/{attempts}: FAILED after ~{approx} ms to {host}:{port}"");
                    }

                    if (i < attempts && delayMs > 0)
                    {
                        await Task.Delay(delayMs, cancellationToken);
                    }
                }

                return new ResultObj
                {
                    Success = anySuccess,
                    Message = sb.ToString()
                };
            }
            catch (OperationCanceledException)
            {
                return new ResultObj { Success = false, Message = ""TCP check canceled or timed out.\n"" };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ""TcpPortCheck error"");
                return new ResultObj { Success = false, Message = $""TCP check error: {ex.Message}"" };
            }
        }

        public override string GetCommandHelp()
        {
            var header = ""Checks TCP connectivity to a host:port with schema-based parsing.\n"";
            var usage  = CliArgParser.BuildUsage(_cmdProcessorStates.CmdDisplayName, _schema);
            var examples = @"" 
Examples:
  --host example.com --port 443
  --host 8.8.8.8 --port 53 --attempts 3 --timeout_ms 2000 --delay_ms 250
"";
            return $""{header}\n{usage}\n{examples}"";
        }

        private static async Task<bool> TryConnect(string host, int port, int timeoutMs, CancellationToken ct)
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);

            try
            {
#if NET8_0_OR_GREATER
                await client.ConnectAsync(host, port, cts.Token);
#else
                var connectTask = client.ConnectAsync(host, port);
                var completed = await Task.WhenAny(connectTask, Task.Delay(timeoutMs, cts.Token));
                if (completed != connectTask)
                {
                    try { client.Close(); } catch { }
                    cts.Cancel();
                    return false;
                }
                await connectTask;
#endif
                return client.Connected;
            }
            catch
            {
                return false;
            }
        }
    }
}
        ]]>
        </source_code>
        <agent_location>Scanner - US</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: added TcpPortCheck cmd processor"", ""success"" : true, ""agent_location"" : ""Scanner - US"" }",
                "add_cmd_processor"
            );

            messages.Add(ChatMessage.FromAssistant(
                "I have created a schema-based TcpPortCheck cmd processor and it is ready for use on agent Scanner - US"
            ));

            // --------------------------------------------------
            // 4TH GROUP: user -> assistant (with function_call) -> tool
            // Run FTP tester with schema flags
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Can you check if ftp ftpsite.com is working I use username test password test123",
                @"<function_call name=""run_cmd_processor"">
    <parameters>
        <cmd_processor_type>FTPConnectionTester</cmd_processor_type>
        <arguments>--host ftpsite.com --username test --password test123</arguments>
        <agent_location>Scanner - US</agent_location>
    </parameters>
</function_call>",
                @"{""message"": ""Success: ftpsite.com connection success"", ""success"": true, ""agent_location"": ""Scanner - US""}",
                "run_cmd_processor"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The FTP connection to ftpsite.com was successful."
            ));

            // --------------------------------------------------
            // 5TH GROUP: user -> assistant (with function_call) -> tool
            // Delete List
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Please delete the List cmd processor.",
                @"<function_call name=""delete_cmd_processor"">
    <parameters>
        <cmd_processor_type>List</cmd_processor_type>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: deleted List cmd processor"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "delete_cmd_processor"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The List cmd processor has been removed from the agent."
            ));

            // --------------------------------------------------
            // 6TH GROUP: user -> assistant (with function_call) -> tool
            // Delete FTPConnectionTester
            // --------------------------------------------------
            AddAssistantMessageWithToolCall(
                messages,
                "Also, please delete the FTPConnectionTester cmd processor.",
                @"<function_call name=""delete_cmd_processor"">
    <parameters>
        <cmd_processor_type>FTPConnectionTester</cmd_processor_type>
        <agent_location>Scanner - US</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: deleted FTPConnectionTester cmd processor"", ""success"" : true, ""agent_location"" : ""Scanner - US"" }",
                "delete_cmd_processor"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The FTPConnectionTester cmd processor has been removed as well."
            ));

            return messages;
        }

        private static List<ChatMessage> GetConnectXml(params object[] args)
        {
            var messages = new List<ChatMessage>();

            AddAssistantMessageWithToolCall(
                messages,
                "Please add a simple TCP connect check that runs periodically for my monitoring setup on agent London - UK",
                @"<function_call name=""add_connect"">
    <parameters>
        <connect_type>Tcp</connect_type>
        <source_code>
        <![CDATA[
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects;

namespace NetworkMonitor.Connection
{
    public class TcpConnect : NetConnect
    {
        public override async Task Connect()
        {
            Timer.Reset();
            try
            {
                PreConnect();
                Logger?.LogInformation(""TcpConnect starting for {Address}"", MpiStatic.Address);
                var host = MpiStatic.Address;
                var port = MpiStatic.Port == 0 ? 443 : MpiStatic.Port;

                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                Timer.Start();

                var connectTask = socket.ConnectAsync(host, port);
                if (await Task.WhenAny(connectTask, Task.Delay(MpiStatic.Timeout)) != connectTask)
                {
                    ProcessException(""Connection timed out."", ""TimedOut"");
                    return;
                }

                await connectTask;
                Timer.Stop();
                ProcessStatus(""Connected"", (ushort)Timer.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                ProcessException(ex.Message, ""Exception"");
            }
            finally
            {
                PostConnect();
            }
        }
    }
}
        ]]>
        </source_code>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: added Tcp connect"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "add_connect"
            );

            messages.Add(ChatMessage.FromAssistant(
                "I have added a Tcp connect type. You can now use endpoint type 'tcp' when configuring hosts."
            ));

            AddAssistantMessageWithToolCall(
                messages,
                "Please add an API Health Check connect that pings a URL, checks status, and optionally validates JSON or content, on agent London - UK",
                @"<function_call name=""add_connect"">
    <parameters>
        <connect_type>ApiHealth</connect_type>
        <source_code>
        <![CDATA[
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils;

namespace NetworkMonitor.Connection
{
    public class ApiHealthConnect : NetConnect
    {
        private const string ProcessorType = ""HttpProbe"";
        private static readonly List<ArgSpec> _schema = new()
        {
            new() { Key = ""url"", Required = false, IsFlag = false, TypeHint = ""value"", Help = ""API URL (defaults to Address)"" },
            new() { Key = ""method"", Required = false, IsFlag = false, TypeHint = ""value"", DefaultValue = ""GET"", Help = ""HTTP method"" },
            new() { Key = ""status"", Required = false, IsFlag = false, TypeHint = ""int"", DefaultValue = ""200"", Help = ""Expected HTTP status code"" },
            new() { Key = ""jsonKey"", Required = false, IsFlag = false, TypeHint = ""value"", Help = ""JSON key path to check (dot-separated)"" },
            new() { Key = ""contains"", Required = false, IsFlag = false, TypeHint = ""value"", Help = ""Substring that must appear in response body"" }
        };

        public override async Task Connect()
        {
            PreConnect();
            Timer.Reset();

            try
            {
                var parsed = CliArgParser.Parse(MpiStatic.Args ?? string.Empty, _schema);
                if (!parsed.Success)
                {
                    ProcessException(parsed.Message, ""BadArgs"");
                    return;
                }

                Logger?.LogInformation(""ApiHealthConnect running with args: {Args}"", MpiStatic.Args);
                string url = parsed.GetString(""url"", MpiStatic.Address);
                if (!url.StartsWith(""http"", StringComparison.OrdinalIgnoreCase))
                {
                    url = ""https://"" + url;
                }

                string method = parsed.GetString(""method"", ""GET"").ToUpperInvariant();
                int expectedStatus = parsed.GetInt(""status"", 200);
                string jsonKey = parsed.GetString(""jsonKey"", """");
                string contains = parsed.GetString(""contains"", """");

                var processor = CmdProcessorProvider?.GetProcessor(ProcessorType);
                if (processor == null)
                {
                    ProcessException($""Cmd processor '{ProcessorType}' not available"", ""NoProcessor"");
                    return;
                }

                var args = $""--url {url} --method {method} --status {expectedStatus}"";
                if (!string.IsNullOrWhiteSpace(jsonKey))
                {
                    args += $"" --jsonKey {jsonKey}"";
                }
                if (!string.IsNullOrWhiteSpace(contains))
                {
                    args += $"" --contains {contains}"";
                }

                var result = await processor.RunCommand(args, Cts.Token, null);
                if (!result.Success)
                {
                    ProcessException(result.Message ?? ""Probe failed"", ""ProbeFailed"");
                    return;
                }

                Timer.Stop();
                ProcessStatus(""API OK"", (ushort)Timer.ElapsedMilliseconds, result.Message ?? string.Empty);
            }
            catch (OperationCanceledException)
            {
                ProcessException(""Timeout"", ""Timeout"");
            }
            catch (Exception ex)
            {
                ProcessException(ex.Message, ""Exception"");
            }
            finally
            {
                PostConnect();
            }
        }
    }
}
        ]]>
        </source_code>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: added ApiHealth connect"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "add_connect"
            );

            messages.Add(ChatMessage.FromAssistant(
                "I have added the ApiHealth connect type. Configure it via Args (e.g., --url https://api.example.com --method GET --status 200 --jsonKey data.ok --contains healthy)."
            ));

            AddAssistantMessageWithToolCall(
                messages,
                "What connect types are available on agent London - UK?",
                @"<function_call name=""get_connect_list"">
    <parameters>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: got the list of connect types for the agent. connect_types : ['icmp','http','https','tcp']"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "get_connect_list"
            );

            messages.Add(ChatMessage.FromAssistant(
                "Here is the current connect type list for London - UK."
            ));

            AddAssistantMessageWithToolCall(
                messages,
                "Please delete the Tcp connect type.",
                @"<function_call name=""delete_connect"">
    <parameters>
        <connect_type>Tcp</connect_type>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: deleted Tcp connect type"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "delete_connect"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The Tcp connect type has been removed from the agent."
            ));

            AddAssistantMessageWithToolCall(
                messages,
                "Please delete the ApiHealth connect type.",
                @"<function_call name=""delete_connect"">
    <parameters>
        <connect_type>ApiHealth</connect_type>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: deleted ApiHealth connect type"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "delete_connect"
            );

            messages.Add(ChatMessage.FromAssistant(
                "The ApiHealth connect type has been removed from the agent."
            ));

            AddAssistantMessageWithToolCall(
                messages,
                "Create a new connect that runs a complex TLS scan using a cmd processor. If the cmd processor does not exist, create it first.",
                @"<function_call name=""call_cmd_processor_expert"">
    <parameters>
        <message>""Create a cmd processor named TlsDeepScan that runs a detailed TLS scan for a target host and port using schema-based args: --target (required), --port (default 443), --timeout (ms). Return a concise summary. Confirm authorized to create it.""</message>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: added TlsDeepScan cmd processor"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "call_cmd_processor_expert"
            );

            AddAssistantMessageWithToolCall(
                messages,
                "Now add a connect that invokes the TlsDeepScan cmd processor for each host.",
                @"<function_call name=""add_connect"">
    <parameters>
        <connect_type>TlsDeepConnect</connect_type>
        <source_code>
        <![CDATA[
using System;
using System.Threading.Tasks;
using NetworkMonitor.Objects;

namespace NetworkMonitor.Connection
{
    public class TlsDeepConnect : NetConnect
    {
        private const string ProcessorType = ""TlsDeepScan"";

        public override async Task Connect()
        {
            PreConnect();
            Timer.Reset();

            try
            {
                var processor = CmdProcessorProvider?.GetCmdProcessor(ProcessorType);
                if (processor == null)
                {
                    ProcessException($""Cmd processor '{ProcessorType}' not available"", ""NoProcessor"");
                    return;
                }

                var port = MpiStatic.Port == 0 ? 443 : MpiStatic.Port;
                var args = $""--target {MpiStatic.Address} --port {port} --timeout {MpiStatic.Timeout}"";
                var result = await processor.RunCommand(args, Cts.Token, null);
                if (!result.Success)
                {
                    ProcessException(result.Message ?? ""Scan failed"", ""ScanFailed"");
                    return;
                }

                Timer.Stop();
                ProcessStatus(""TLS scan complete"", (ushort)Timer.ElapsedMilliseconds, result.Message ?? string.Empty);
            }
            catch (OperationCanceledException)
            {
                ProcessException(""Timeout"", ""Timeout"");
            }
            catch (Exception ex)
            {
                ProcessException(ex.Message, ""Exception"");
            }
            finally
            {
                PostConnect();
            }
        }
    }
}
        ]]>
        </source_code>
        <agent_location>London - UK</agent_location>
    </parameters>
</function_call>",
                @"{""message"" : ""Success: added TlsDeepConnect connect"", ""success"" : true, ""agent_location"" : ""London - UK"" }",
                "add_connect"
            );

            messages.Add(ChatMessage.FromAssistant(
                "I have added the TlsDeepConnect connect type, which calls the TlsDeepScan cmd processor."
            ));

            return messages;
        }

        private static List<ChatMessage> GetConnectPrompt(params object[] args)
        {
            return GetConnectXml(args);
        }

        private static List<ChatMessage> GetAgentFlowPrompt(params object[] args)
        {
            var messages = new List<ChatMessage>();
            const string flowJson = "{\"version\":1,\"startNode\":\"get_targets\",\"initState\":{\"agent_location\":\"Scanner - EU\"},\"nodes\":[{\"id\":\"get_targets\",\"type\":\"template-llm\",\"toolSpecId\":\"monitor-tool\",\"promptTemplate\":\"Call get_host_list to retrieve enabled monitored hosts. Output targets as a comma-separated string in key 'targets'. If no hosts are found, return an empty string.\",\"outputs\":[\"targets\"],\"next\":\"run_nmap\"},{\"id\":\"run_nmap\",\"type\":\"template-llm\",\"toolSpecId\":\"monitor-tool\",\"promptTemplate\":\"Use scan_options '-sT -sV --open --top-ports 100 --max-retries 1'. Call run_nmap with target={{targets}}, scan_options as strings, and agent_location={{agent_location}}. Save the raw output in 'nmap_results'.\",\"requires\":[\"targets\",\"agent_location\"],\"outputs\":[\"nmap_results\"],\"next\":null}],\"toolSpecs\":[{\"id\":\"monitor-tool\",\"systemPrompt\":\"Use get_host_list and run_nmap only. Return raw tool outputs for downstream steps.\",\"functions\":[\"get_host_list\",\"run_nmap\"]}]}";
            var arguments = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["flow_name"] = "quick-scan",
                ["json"] = flowJson,
                ["overwrite"] = true
            });

            AddAssistantMessageWithToolCall(
                messages,
                "Create a small agent flow that lists monitored hosts and runs a fast nmap scan.",
                "",
                "{\"message\":\"Flow saved.\",\"success\":true}",
                "add_agent_flow",
                arguments
            );

            messages.Add(ChatMessage.FromAssistant(
                "I created the flow and saved it. It calls get_host_list to build a comma-separated targets string, then runs run_nmap with explicit scan_options."
            ));

            return messages;
        }

        // Example placeholder for additional prompts
        private static List<ChatMessage> GetDefaultPrompt(params object[] args)
        {
            var messages = new List<ChatMessage>();

            if (args.Length < 3)
            {
                throw new ArgumentException("GetDefaultPrompt requires at least three arguments: current time and LLMServiceObj instance.");
            }

            // Extract currentTime
            string currentTime = args[0]?.ToString() ?? "unknown";

            // Safely retrieve the LLMServiceObj instance
            var serviceObj = args.Length > 1 && args[1] is LLMServiceObj obj ? obj : new LLMServiceObj();
            var config = args.Length > 2 && args[2] is LLMConfig lmobj ? lmobj : new LLMConfig();
            // Initialize the content variable
            string content;

            // Determine if the user is logged in and generate content accordingly
            if (serviceObj.IsUserLoggedIn)
            {
                content = $"The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}. " +
           $"Users account type is {serviceObj.UserInfo.AccountType}. They have {serviceObj.UserInfo.TokensUsed} available tokens. " +
           $"Remind the user that upgrading accounts gives more tokens and access to more functions. " +
           $"See {AppConstants.FrontendUrl}/subscription for details.";
            }
            else
            {
                content = $"The user is not logged in, the time is {currentTime}. " +
                          $"They don't need to be logged in, but to add hosts they will need to supply an email address. " +
                          $"All other functions can be called with or without an email address." +
                          $"If the user asks about logging in then they can browse to [Quantum Network Monitor]({AppConstants.FrontendUrl}/#assistant=open&openInNewTab) and then click the login button top right";
            }
            string arguments = @"{""detail_response"" : false}";

            // Add messages using the helper method
            AddAssistantMessageWithToolCall(
                messages,
                // userPrompt
                "What’s my user info?",
                // assistantPrompt
                "",
                // toolResponse (tool response in JSON format)
                $@"{{
            ""message"": ""Got user info"",
            ""success"": true,
            ""current_time"": ""{currentTime}"",
            ""email"": ""{serviceObj.UserInfo.Email}"",
            ""account_type"": ""{serviceObj.UserInfo.AccountType}"",
            ""available_tokens"": {serviceObj.UserInfo.TokensUsed},
            ""logged_in"": {serviceObj.IsUserLoggedIn.ToString().ToLower()}
        }}",
                // functionName
                "get_user_info",
                arguments
            );

            messages.Add(ChatMessage.FromAssistant(
              content
          ));

            return messages;
        }
        private static List<ChatMessage> GetUserSimulatorPrompt(params object[] args)
        {
            var messages = new List<ChatMessage>();

            if (args.Length < 3)
            {
                throw new ArgumentException("GetUserSimulatorPrompt requires at least three arguments: current time, LLMServiceObj instance, and LLMConfig.");
            }

            // Extract arguments
            string currentTime = args[0]?.ToString() ?? "unknown";
            var serviceObj = args.Length > 1 && args[1] is LLMServiceObj obj ? obj : new LLMServiceObj();
            var config = args.Length > 2 && args[2] is LLMConfig lmobj ? lmobj : new LLMConfig();

            // Initialize the content variable
            string funcResponse;

            // Determine if the user is logged in and generate content accordingly
            if (serviceObj.IsUserLoggedIn)
            {
                funcResponse = $"The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}. " +
             $"Users account type is {serviceObj.UserInfo.AccountType}. They have {serviceObj.UserInfo.TokensUsed} available tokens. " +
             $"Remind the user that upgrading accounts gives more tokens and access to more functions. " +
             $"See {AppConstants.FrontendUrl}/subscription for details.";
            }
            else
            {
                funcResponse = $"The user is not logged in, the time is {currentTime}. " +
                          $"They don't need to be logged in, but to add hosts they will need to supply an email address. " +
                          $"All other functions can be called with or without an email address.";
            }

            // Single N-shot example: Request user info
            string arguments = @"{{""message"": ""What's my user info?""}}";

            AddAssistantMessageWithToolCall(
                messages,
                null,
                "",
                // assistantPrompt (function call response)
                funcResponse,
                // functionName
                "call_monitor_sys"
                , arguments
            );


            string arguments2 = @"{{""message"": ""What can you do?""}}";
            string funcResponse2 = @$"I am a network monitoring and security assistant designed to help you manage and secure your network infrastructure. Here's what I can do:

1. **Host Monitoring**  
   - Add, edit, and monitor hosts for uptime, SSL certificates, and more.  
   - Monitor endpoints like HTTP, HTTPS, DNS, SMTP, and ICMP.  
   - Perform simulated user crawls to test website performance.  

2. **Security Assessments**  
   - Run vulnerability scans using Nmap.  
   - Test SSL/TLS configurations for weaknesses.  
   - Perform penetration testing with Metasploit.  

3. **Quantum Security**  
   - Validate quantum-safe encryption on your servers.  
   - Test TLS KEM support and post-quantum certificate usage.  

4. **Network Diagnostics**  
   - Run BusyBox commands for network troubleshooting (e.g., ping, ifconfig).  
   - Gather real-time network performance data.  

5. **Custom Command Processors**  
   - Create, manage, and run custom .NET command processors on your agents.  
   - View and modify source code for custom processors.  

6. **Search and Information Retrieval**  
   - Perform web searches and retrieve information from URLs.  
   - Read and summarize web page content.  

7. **Alert Management**  
   - Configure email alerts for host downtime or security issues.  
   - Update alert settings and notification preferences.  

8. **Agent Management**  
   - Retrieve details about monitoring agents.  
   - Assign tasks to specific agents based on location or capability.  

9. **User and Account Management**  
   - Provide user information, including account type and token usage.  
   - Guide users on upgrading their accounts for additional features.  

10. **Real-time Monitoring and Reporting**  
    - Provide detailed monitoring data for hosts.  
    - Generate reports on network performance and security status.  

If you need help with any of these tasks, just let me know! You can also visit {AppConstants.FrontendUrl}/subscription to upgrade your account and unlock more features.";


            AddAssistantMessageWithToolCall(
                messages,
                null,
                "",
                // assistantPrompt (function call response)
                funcResponse2,
                // functionName
                "call_monitor_sys",
                arguments2
            );


            return messages;
        }
    }
}

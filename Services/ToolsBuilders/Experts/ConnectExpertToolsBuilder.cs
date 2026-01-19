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
    public class ConnectExpertToolsBuilder : ToolsBuilderBase
    {
        private readonly FunctionDefinition fn_get_connect_list;
        private readonly FunctionDefinition fn_get_connect_source_code;
        private readonly FunctionDefinition fn_add_connect;
        private readonly FunctionDefinition fn_delete_connect;

        public ConnectExpertToolsBuilder()
        {
            fn_get_connect_list = ConnectTools.BuildListFunction();
            fn_get_connect_source_code = ConnectTools.BuildSourceCodeFunction();
            fn_add_connect = ConnectTools.BuildAddFunction();
            fn_delete_connect = ConnectTools.BuildDeleteFunction();

            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_get_connect_list, Type = "function" },
                new ToolDefinition() { Function = fn_get_connect_source_code, Type = "function" },
                new ToolDefinition() { Function = fn_add_connect, Type = "function" },
                new ToolDefinition() { Function = fn_delete_connect, Type = "function" }
            };
        }

        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string overridePrompt = @"You are an automated Connect manager operating within the Network Monitor Assistant. You create and manage Connect types that run periodically as part of the monitoring loop (not one-off commands).
A Connect is a .NET class that implements an endpoint check and is invoked by the monitoring engine on schedule.";

            string contentPart2 = @" If the user requests to add a connect, call the function add_connect with parameters connect_type, the agent_location.

The user can also: delete a connect (delete_connect), or view the .NET source code that the connect runs (get_connect_source_code).

The user can also request to see what connect types are currently available by calling get_connect_list with the agent location.

You will not ask the user to supply the source code when adding or updating a connect. When the user requests a new or updated connect it is your job as the connect expert to take the users request and convert that as best as you can, without question, to .NET source code and then add the connect.

Connects are periodic checks used by monitored hosts. They are not run directly; they are used when a host is configured with a matching endpoint type.";

            string content = overridePrompt + contentPart2;
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

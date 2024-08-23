using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using OpenAI;
using OpenAI.Builders;
using OpenAI.Managers;
using OpenAI.ObjectModels;
using OpenAI.ObjectModels.RequestModels;
using OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services
{
    public class MetasploitToolsBuilder : IToolsBuilder
    {
        private readonly FunctionDefinition fn_get_user_info;
        private readonly FunctionDefinition fn_run_metasploit;

        public MetasploitToolsBuilder()
        {
            // Define the get_user_info function
            fn_get_user_info = new FunctionDefinitionBuilder("get_user_info", "Get information about the user")
                .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all user details. Set to false if only basic info is required"))
                .Validate()
                .Build();

            // Define the run_metasploit function
            fn_run_metasploit = new FunctionDefinitionBuilder("run_metasploit", "This function calls Metasploit to execute a module. Create the parameters based upon the user's request.")
                .AddParameter("module_name", PropertyDefinition.DefineString("The name of the Metasploit module to run, required. For example, 'exploit/windows/smb/ms17_010_eternalblue'."))
                .AddParameter("module_options", PropertyDefinition.DefineObject("The options for the module, optional. These options should be passed as key-value pairs to configure the Metasploit module. Examples include 'RHOSTS', 'RPORT', 'PAYLOAD', etc."))
                .AddParameter("target", PropertyDefinition.DefineString("The target, required. This is typically the IP address, range, or domain you wish to target."))
                .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the module, optional. Specify this if the Metasploit execution is to be performed by a specific remote agent."))
                .Validate()
                .Build();

            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_get_user_info, Type = "function" },
                new ToolDefinition() { Function = fn_run_metasploit, Type = "function" }
            };
        }

        private readonly List<ToolDefinition> _tools;

        public List<ToolDefinition> Tools => _tools;

        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
        {
           string content = "You are a penetration testing assistant specializing in the Metasploit framework. Your primary task is to translate user requests into the appropriate Metasploit module and options, and call the Metasploit functions. "
                           + "When setting up a Metasploit module, ensure that the `module_options` parameter is an object containing key-value pairs. Each key represents an option name like `RHOSTS`, `RPORT`, `PAYLOAD`, and each value represents the corresponding configuration.";
                           + "Always confirm the correct module and options to be used based on the user's intent.";

            if (serviceObj.IsUserLoggedIn)
            {
                content += $" The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}.";
            }
            else
            {
                content += $" The user is not logged in, the time is {currentTime}, ask the user for an email to add hosts etc.";
            }

            var chatMessage = new ChatMessage()
            {
                Role = "system",
                Content = content
            };
            var chatMessages = new List<ChatMessage>();
            chatMessages.Add(chatMessage);
            return chatMessages;
        }
    }
}

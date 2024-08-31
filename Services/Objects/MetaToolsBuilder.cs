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
    public class MetaToolsBuilder : IToolsBuilder
    {
       private readonly FunctionDefinition fn_run_metasploit;
        private readonly FunctionDefinition fn_search_metasploit_modules;
        private readonly FunctionDefinition fn_get_user_info;

        public MetaToolsBuilder()
        {
            // Define the run_metasploit function
           // Define the run_metasploit function
fn_run_metasploit = new FunctionDefinitionBuilder("run_metasploit", "This function executes a Metasploit module based on the user's specifications. Use it to perform tasks such as exploiting a vulnerability, conducting scans, or gathering post-exploitation data.")
    .AddParameter("module_name", PropertyDefinition.DefineString("The name of the Metasploit module to run, required. Examples include 'exploit/windows/smb/ms17_010_eternalblue' for the EternalBlue vulnerability."))
    .AddParameter("module_options", PropertyDefinition.DefineObject(
        new Dictionary<string, PropertyDefinition>(),
        null,
        false,
        "The options for the module, optional. These should be key-value pairs to configure the module, such as 'RHOSTS' for the target IP address, 'PAYLOAD' for the payload to use, and 'LHOST' for the attacker's IP in reverse shell scenarios.",
        null
    ))
    .AddParameter("target", PropertyDefinition.DefineString("The target, required. Specify the IP address, range, or domain you wish to target."))
    .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the module, optional. Use this if you need the module to be executed from a specific network segment or geographic location."))
    .Validate()
    .Build();

// Define the search_metasploit_modules function
fn_search_metasploit_modules = new FunctionDefinitionBuilder("search_metasploit_modules", "Search for information about Metasploit modules or retrieve details about a specific module. Use this function when you need to identify the appropriate module, gather more details on a module's usage, or troubleshoot errors.")
    .AddParameter("number_lines", PropertyDefinition.DefineInteger("The maximum number of lines to return in the search results. Increase this if more data is needed. Be cautious with large numbers to avoid overwhelming the system with excessive data."))
    .AddParameter("search_type", PropertyDefinition.DefineString("The search type to use. Valid values are 'search' for keyword-based searches, 'show' to list all modules of a specific type, and 'info' to retrieve detailed information about a specific module."))
    .AddParameter("search_expression", PropertyDefinition.DefineString("The search expression to use, based on the search type. Examples: 'type:exploit platform:windows cve:2021' for 'search', 'exploits' for 'show', or 'exploit/windows/smb/ms17_010_eternalblue' for 'info'."))
    .Validate()
    .Build();

            // Define the get_user_info function
            fn_get_user_info = new FunctionDefinitionBuilder("get_user_info", "Get information about the user")
                .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all user details. Set to false if only basic info is required"))
                .Validate()
                .Build();

            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_get_user_info, Type = "function" },
                new ToolDefinition() { Function = fn_run_metasploit, Type = "function" },
                new ToolDefinition() { Function = fn_search_metasploit_modules, Type = "function" }
            };
        }

        private readonly List<ToolDefinition> _tools;

        public List<ToolDefinition> Tools => _tools;

      public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
{
    string content = "You are an advanced penetration testing assistant specializing in the Metasploit framework. Your primary task is to help users achieve their goals by selecting and configuring the appropriate Metasploit modules based on their requests. "
                   + "You should always prioritize accurate, efficient, and safe operations. Utilize your knowledge of Metasploit to guide users and ensure that each action is aligned with best practices in penetration testing. "
                   + "If the user provides a target, ensure you select the appropriate Metasploit module considering the target's operating system, service, and known vulnerabilities. "
                   + "Whenever possible, prefer non-destructive information gathering over active exploitation. If an action might be harmful, suggest safer alternatives and warn the user.";

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

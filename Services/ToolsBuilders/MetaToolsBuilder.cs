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
        private readonly FunctionDefinition fn_run_busybox;
        private readonly FunctionDefinition fn_run_search_web;
        private readonly FunctionDefinition fn_run_crawl_page;

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
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Increase this if you need more data returned by the search. Be careful with using larger numbers as a lot of data can be returned. Consider using a more targeted search term instead."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data."))
                .Validate()
                .Build();

            // Define the search_metasploit_modules function
            fn_search_metasploit_modules = new FunctionDefinitionBuilder("search_metasploit_modules", "Search for information about Metasploit modules or retrieve details about a specific module. Use this function when you need to identify the appropriate module, gather more details on a module's usage, or troubleshoot errors.")
                .AddParameter("search_type", PropertyDefinition.DefineString("The search type to use. Valid values are 'search' for keyword-based searches, 'show' to list all modules of a specific type, and 'info' to retrieve detailed information about a specific module."))
                .AddParameter("search_expression", PropertyDefinition.DefineString("The search expression to use, based on the search type. Examples: 'type:exploit platform:windows cve:2021' for 'search', 'exploits' for 'show', or 'exploit/windows/smb/ms17_010_eternalblue' for 'info'."))
                 .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return. Increase this if you need more data returned by the search. Be careful with using larger numbers as a lot of data can be returned. Consider using a more targeted search term instead."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data."))
                .Validate()
                .Build();

            // Define the get_user_info function
            fn_get_user_info = new FunctionDefinitionBuilder("get_user_info", "Get information about the user")
                .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all user details. Set to false if only basic info is required"))
                .Validate()
                .Build();
            fn_run_busybox = new FunctionDefinitionBuilder("run_busybox_command", "Run a BusyBox command. Use BusyBox utilities to assist with other functions of the assistant as well as user requests. For instance, you might use BusyBox to gather network diagnostics, troubleshoot connectivity issues, monitor system performance, or perform basic file operations in response to a user's request.")
    .AddParameter("command", PropertyDefinition.DefineString("The BusyBox command to be executed. Example commands: 'ls /tmp' to list files in the /tmp directory, 'ping -c 4 8.8.8.8' to ping Google's DNS server 4 times, or 'ifconfig' to display network interface configurations."))
    .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
    .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return from the command output. Use this parameter to limit the output. Larger values may return extensive data, so use higher limits cautiously."))
    .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use this to paginate through multiple lines of output if the command returns more data than the specified number of lines."))
    .Validate()
    .Build();

            fn_run_search_web = new FunctionDefinitionBuilder("run_search_web",
            "Search function to gather information from web sources. Use this function to perform a Google search and retrieve a list of websites related to the search term. After retrieving the URLs, you must call the 'run_crawl_page' function to visit and gather details from each site. The search results are intended to guide the selection of relevant links for deeper exploration.")
            .AddParameter("search_term", PropertyDefinition.DefineString("The search term to be used for the Google search."))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return from the command output. Limit this to manage the amount of search results returned. Larger values may retrieve more links, but use higher limits cautiously."))
            .AddParameter("page", PropertyDefinition.DefineInteger("The page of search results to return, allowing pagination through multiple search results pages."))
            .Validate()
            .Build();


            fn_run_crawl_page = new FunctionDefinitionBuilder("run_crawl_page",
                   "Website crawler to extract information from a webpage. Use this function to read the text and hyperlinks on a given webpage. When URLs are returned from 'run_search_web', call this function on relevant URLs to gather content. If necessary, you can follow additional links on the page to perform further research.")
                   .AddParameter("url", PropertyDefinition.DefineString("The URL of the page to crawl."))
                   .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
                   .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return from the command output. Limit this to manage the amount of content returned."))
                   .AddParameter("page", PropertyDefinition.DefineInteger("The page of content to return, allowing pagination through large pages of data."))
                   .Validate()
                   .Build();




            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                new ToolDefinition() { Function = fn_get_user_info, Type = "function" },
                new ToolDefinition() { Function = fn_run_metasploit, Type = "function" },
                new ToolDefinition() { Function = fn_search_metasploit_modules, Type = "function" },
                 new ToolDefinition() { Function = fn_run_busybox, Type = "function" },
                   new ToolDefinition() { Function = fn_run_search_web, Type = "function" },
                     new ToolDefinition() { Function = fn_run_crawl_page, Type = "function" },

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

            var chatMessage = ChatMessage.FromSystem(content);
            var chatMessages = new List<ChatMessage>();
            chatMessages.Add(chatMessage);
            return chatMessages;
        }

    }
}

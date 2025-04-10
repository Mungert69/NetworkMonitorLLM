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

public class PenetrationTools{

     public static FunctionDefinition BuildRunMetasploitFunction()
    {
        return new FunctionDefinitionBuilder("run_metasploit", "This function executes a Metasploit module based on the user's specifications. Use it to perform tasks such as exploiting a vulnerability, conducting scans, or gathering post-exploitation data.")
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
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return."))
                .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use to paginate through many lines of data."))
                .Validate()
                .Build();}

         public static FunctionDefinition BuildSearchMetasploitFunction()
    {
        return new FunctionDefinitionBuilder("search_metasploit_modules", "Search for Metasploit modules using msfconsole's search command. Provide any combination of search filters to narrow down the results. This function constructs the msfconsole search command based on the provided parameters.")
                .AddParameter("module_type", PropertyDefinition.DefineString("Module type to search for. Options include 'exploit', 'auxiliary', 'post', 'payload', 'encoder', 'nop'. Corresponds to the 'type' search filter."))
                .AddParameter("platform", PropertyDefinition.DefineString("Platform to search for. Examples include 'windows', 'linux', 'multi', etc. Corresponds to the 'platform' search filter."))
                .AddParameter("architecture", PropertyDefinition.DefineString("Architecture to search for. Examples include 'x86', 'x64'. Corresponds to the 'arch' search filter."))
                .AddParameter("cve", PropertyDefinition.DefineString("CVE identifier to search for. Format: 'CVE-YYYY-NNNN'. Corresponds to the 'cve' search filter."))
                .AddParameter("edb", PropertyDefinition.DefineString("Exploit-DB ID to search for. Corresponds to the 'edb' search filter."))
                .AddParameter("rank", PropertyDefinition.DefineString("Minimum rank of modules to include. Options include 'excellent', 'great', 'good', 'normal', 'average', 'low', 'manual'. Corresponds to the 'rank' search filter."))
                .AddParameter("keywords", PropertyDefinition.DefineString("Keywords to search for in module names and descriptions."))
                .AddParameter("number_lines", PropertyDefinition.DefineInteger("Limit the number of lines returned in the search results. Use this to control output size, especially when the search yields many results. For example, setting this to 20 will return the first 20 matching modules."))
                .AddParameter("page", PropertyDefinition.DefineInteger("Specify the page number to paginate through large search results. Use in conjunction with number_lines to navigate sequentially through results, e.g., page 2 will show results after the first number_lines matches."))
                .Validate()
                .Build();}

          public static FunctionDefinition BuildMetasploitModuleInfoFunction()
    {
        return new FunctionDefinitionBuilder("get_metasploit_module_info", "Retrieve detailed information about a specific Metasploit module. Use this function to understand how to configure and use a module, including its options and supported targets.")
                .AddParameter("module_name", PropertyDefinition.DefineString("The full name of the Metasploit module to retrieve information for. Examples include 'exploit/windows/smb/ms17_010_eternalblue'."))
                .Validate()
                .Build();
         }
}
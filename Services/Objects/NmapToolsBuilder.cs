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
using System.Net.Mime;

namespace NetworkMonitor.LLM.Services;
public class NmapToolsBuilder : IToolsBuilder
{
    private readonly FunctionDefinition fn_get_user_info;
    private readonly FunctionDefinition fn_run_nmap;
    public NmapToolsBuilder()
    {

        fn_get_user_info = new FunctionDefinitionBuilder("get_user_info", "Get information about the user")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all user details. Set to false if only basic info is required"))
        .Validate()
        .Build();


        fn_run_nmap = new FunctionDefinitionBuilder("run_nmap", "This function calls nmap. Create the parameterse based upon the users request. The response from the function will contains a result with the output of running nmap on the remote agent. Give the user a summary of the output that answers their query")
      .AddParameter("scan_options", PropertyDefinition.DefineString("Scan options, required"))
      .AddParameter("target", PropertyDefinition.DefineString("The target, required"))
      .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the scan, optional"))
      .Validate()
      .Build();

      _tools = new List<ToolDefinition>()
        {
            new ToolDefinition() { Function = fn_get_user_info, Type="function"  },
            new ToolDefinition() { Function = fn_run_nmap, Type="function"  }
        };

    }


    private readonly List<ToolDefinition> _tools;

    public List<ToolDefinition> Tools => _tools;

    public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        string content = "You are a network scanning assistant specializing in network scanning using nmap. Your primary task is to translate user requests into the appropriate nmap command and call the nmap functions.";

        if (serviceObj.IsUserLoggedIn) content += $" The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}.";
        else { content += $" The user is not logged in, the time is {currentTime}, ask the user for an email to add hosts etc."; }

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

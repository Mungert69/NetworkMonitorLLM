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
public class ToolsBuilder
{
    private static FunctionDefinition fn_add_host = new FunctionDefinitionBuilder("add_host", "Add a new host to be monitored")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Include full details in response ,optional"))
       .AddParameter("address", PropertyDefinition.DefineString("The host address ,required"))
        .AddParameter("endpoint", PropertyDefinition.DefineEnum(
            new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect" },
            "The endpoint type to monitor ,optional"))
        .AddParameter("port", PropertyDefinition.DefineNumber("Service port to monitor ,optional"))
        .AddParameter("timeout", PropertyDefinition.DefineNumber("Timeout for connection in milliseconds ,optional"))
        .AddParameter("email", PropertyDefinition.DefineString("Email for alerts, optional if logged in, required if not"))
        .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional. If this is left blank an agent_location will be assigned"))
        .Validate()
        .Build();


    private static FunctionDefinition fn_edit_host = new FunctionDefinitionBuilder("edit_host", "Edit a host's monitoring configuration")
         .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Include full details in response ,optional"))
       .AddParameter("auth_key", PropertyDefinition.DefineString("Authentication key for unauthenticated edits ,optional"))
        .AddParameter("id", PropertyDefinition.DefineNumber("Host ID for identification ,optional"))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean("Host monitoring status ,optional"))
        .AddParameter("address", PropertyDefinition.DefineString("Host address ,optional"))
        .AddParameter("endpoint", PropertyDefinition.DefineEnum(
            new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect" },
            "The endpoint type to monitor ,optional"))
        .AddParameter("port", PropertyDefinition.DefineNumber("Service port to monitor ,optional"))
        .AddParameter("timeout", PropertyDefinition.DefineNumber("Timeout for connection in milliseconds ,optional"))
        .AddParameter("hidden", PropertyDefinition.DefineBoolean("Hide the host from monitoring view ,optional"))
         .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
        .Validate()
        .Build();

    private static FunctionDefinition fn_get_host_data = new FunctionDefinitionBuilder("get_host_data", "Retrieve monitoring data for a host")
         .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Include full details in response ,optional"))
       .AddParameter("dataset_id", PropertyDefinition.DefineNumber("Dataset ID, 0 for latest ,optional"))
        .AddParameter("id", PropertyDefinition.DefineNumber("The host ID ,optional"))
        .AddParameter("address", PropertyDefinition.DefineString("The host address ,optional"))
        .AddParameter("email", PropertyDefinition.DefineString("Email associated with hosts ,optional"))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean("Filter by enabled status ,optional"))
        .AddParameter("port", PropertyDefinition.DefineNumber("Filter by port ,optional"))
        .AddParameter("endpoint", PropertyDefinition.DefineString("Filter by endpoint type ,optional"))
        .AddParameter("alert_sent", PropertyDefinition.DefineBoolean("Filter by alert sent flag ,optional"))
        .AddParameter("alert_flag", PropertyDefinition.DefineBoolean("Filter by up/down status ,optional"))
        .AddParameter("date_start", PropertyDefinition.DefineString("Start date in ISO 8601 ,optional"))
        .AddParameter("date_end", PropertyDefinition.DefineString("End date in ISO 8601 ,optional"))
        .AddParameter("page_number", PropertyDefinition.DefineNumber("Page number for pagination (optional"))
         .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
        .Validate()
        .Build();


    private static FunctionDefinition fn_get_host_list = new FunctionDefinitionBuilder("get_host_list", "Retrieve a list of monitored hosts")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Include full details in response ,optional"))
        .AddParameter("id", PropertyDefinition.DefineNumber("Filter by host ID ,optional"))
        .AddParameter("address", PropertyDefinition.DefineString("Filter by host address ,optional"))
        .AddParameter("email", PropertyDefinition.DefineString("Filter by associated email ,optional"))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean("Filter by enabled status ,optional"))
        .AddParameter("port", PropertyDefinition.DefineNumber("Filter by port ,optional"))
        .AddParameter("endpoint", PropertyDefinition.DefineString("Filter by endpoint type ,optional"))
        .AddParameter("page_number", PropertyDefinition.DefineNumber("Page number for pagination ,optional"))
         .AddParameter("agent_location", PropertyDefinition.DefineString("The location of the agent monitoring this host, optional"))
        .Validate()
        .Build();

    private static FunctionDefinition fn_get_user_info = new FunctionDefinitionBuilder("get_user_info", "Get information about the user")
    .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Include full details in response ,optional"))     
    .Validate()
    .Build();

    private static FunctionDefinition fn_get_agents = new FunctionDefinitionBuilder("get_agents", "Retrieve a list of monitoring agent details")
   .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Include full details in response ,optional"))
   .Validate()
   .Build();


    public static List<ToolDefinition> Tools = new List<ToolDefinition>()
        {
            new ToolDefinition() { Function = fn_add_host, Type="function" },
            new ToolDefinition() { Function = fn_edit_host, Type="function"  },
            new ToolDefinition() { Function = fn_get_host_data, Type="function"  },
            new ToolDefinition() { Function = fn_get_host_list, Type="function"  },
             new ToolDefinition() { Function = fn_get_user_info, Type="function"  },
               new ToolDefinition() { Function = fn_get_agents, Type="function"  },
        };

    public static List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
    {
        string content = "You are a network monitoring assistant. Use the tools where necessary to assist the user. Your name is TurboLLM and you are faster than FreeLLM. "; 
  
         if (serviceObj.IsUserLoggedIn) content += $"The user logged in at {currentTime} with email {serviceObj.UserInfo.Email}";
        else { content += $"The user is not logged in, the time is {currentTime}, ask the user for an email to add hosts etc.";}
       
        var chatMessage = new ChatMessage()
        {
            Role = "system",
            Content = content      };
        var chatMessages = new List<ChatMessage>();
        chatMessages.Add(chatMessage);
        return chatMessages;
    }

}
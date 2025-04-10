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

    public class CommonTools
    {
       

        public static FunctionDefinition BuildGetUserInfoFunction()
        {
            return new FunctionDefinitionBuilder("get_user_info", $"Get user information. Set detail_response true to get the following user information : current_time, logged_in (are they logged in) email, name, account_type, email_verified, disabled_email_alerts (will they receive email alerts), host_limit (how many hosts can they add), turbo_llm_tokens (the number of tokens available for chats messages when talking to you, if the user requires more tokens than the daily topup then direct them to upgrade at [Subscription]({AppConstants.FrontendUrl}/subscription)")
                .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all user details. Set to false if only basic info is required"))
                .Validate()
                .Build();
        }


        public static FunctionDefinition BuildAreFunctionsRunning()
        {
            return new FunctionDefinitionBuilder("are_functions_running", "Check if functions have completed.")
                .AddParameter("message_id", PropertyDefinition.DefineString("The message_id that is associated with the function calls"))
                .AddParameter("auto_check_interval_seconds", PropertyDefinition.DefineInteger("Set this to zero; Unless the user has requested an auto check. If they request an auto check then set to 60 seconds or above to setup periodic auto-checks on the functions status. Warning auto check will use a lot of tokens, only use if requested and warn the user. To cancel a running auto check set this to -1"))
                .Validate()
                .Build();
        }
        public static FunctionDefinition BuildCancelFunctions()
        {
            return new FunctionDefinitionBuilder("cancel_functions", "Cancel running functions with a given message_id")
                .AddParameter("message_id", PropertyDefinition.DefineString("The message_id that is associated with the function calls"))
                .Validate()
                .Build();
        }

        public static FunctionDefinition BuildGetAgentsFunction()
        {
            return new FunctionDefinitionBuilder("get_agents", "Retrieve a list of monitoring agent details. Call this to give the user a list of agents to choose from. Note the agents with the users email address in the strings are the user's local agents used for local network tasks. The other agents (Scanner - EU etc.) are internet based agents. If a local agent is not available direct the user to install any of the agents from this page : https://freenetworkmonitor.click/download ")
                .AddParameter("detail_response", PropertyDefinition.DefineBoolean("Will this function return all agent details. Set to false if only the agent location and function calling capabilities are required. Set to true for full agent details."))
                .Validate()
                .Build();
        }

        public static  FunctionDefinition BuildRunBusyboxFunction()
    {
        return new FunctionDefinitionBuilder("run_busybox_command", "Run a BusyBox command. Use BusyBox utilities to assist with other functions of the assistant as well as user requests. For instance, you might use BusyBox to gather network diagnostics, troubleshoot connectivity issues, monitor system performance, or perform basic file operations in response to a user's request")
            .AddParameter("command", PropertyDefinition.DefineString("The BusyBox command to be executed. Example commands: 'ls /tmp' to list files in the /tmp directory, 'ping -c 4 8.8.8.8' to ping Google's DNS server 4 times, or 'ifconfig' to display network interface configurations."))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will run the busybox command. If no location is specified ask the user to choose from available agents to ensure the scan is executed from the correct network or geographic location."))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return from the command output. Use this parameter to limit the output. Larger values may return extensive data, so use higher limits cautiously."))
            .AddParameter("page", PropertyDefinition.DefineInteger("The page of lines to return. Use this to paginate through multiple lines of output if the command returns more data than the specified number of lines."))
            .Validate()
            .Build();
    }

    }

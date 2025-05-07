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
        return new FunctionDefinitionBuilder("cancel_functions", "Cancel a function that has not yet completed. It will attempt to halt a running function.It will have no effect on a completed function and will not undo the actions that function had taken.")
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

  public static FunctionDefinition BuildRunBusyboxFunction()
{
    return new FunctionDefinitionBuilder("run_busybox_command", 
        "Run BusyBox commands for local network analysis. Key use cases:\n" +
        "1. Interface status: 'ifconfig eth0' | 'ip addr show'\n" +
        "2. Connectivity testing: 'ping -c 4 192.168.1.1' | 'traceroute 10.0.0.5'\n" +
        "3. Network configuration: 'netstat -r' | 'ip route list'\n" +
        "4. DNS validation: 'nslookup gateway.local' | 'dig +short myip.opendns.com'\n" +
        "5. ARP analysis: 'arp -a' | 'ip neigh show'")
    .AddParameter("command", PropertyDefinition.DefineString(
        "BusyBox network diagnostic command. Examples:\n" +
        "- Show all interfaces: 'ip -br addr'\n" +
        "- Ping default gateway: 'ping -c 5 $(ip route | awk '/default/ {print $3}')'\n" +
        "- Trace route to DNS server: 'traceroute 8.8.8.8'"))
    .AddParameter("agent_location", PropertyDefinition.DefineString(
        "Network segment identifier. Examples: 'gateway-node', 'branch-office-switch', 'main-router'"))
    .AddParameter("number_lines", PropertyDefinition.DefineInteger(
        "Output line limit. Example: 20 lines for 'ip addr show' output"))
    .AddParameter("page", PropertyDefinition.DefineInteger(
        "Paginate large outputs. Example: Page 2 of routing table ('netstat -r') results"))
    .Validate()
    .Build();
}

}

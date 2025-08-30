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
        return new FunctionDefinition
        {
            Name = "get_user_info",
            Description = $"Get user information. Set detail_response true to get the following user information : current_time, logged_in (are they logged in) email, name, account_type, email_verified, disabled_email_alerts (will they receive email alerts), host_limit (how many hosts can they add), turbo_llm_tokens (the number of tokens available for chats messages when talking to you, if the user requires more tokens than the daily topup then direct them to upgrade at [Subscription]({AppConstants.FrontendUrl}/subscription)",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["detail_response"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Will this function return all user details. Set to false if only basic info is required"
                    }
                },
                Required = new List<string> { "detail_response" }
            }
        };
    }

    public static FunctionDefinition BuildAreFunctionsRunning()
    {
        return new FunctionDefinition
        {
            Name = "are_functions_running",
            Description = "Check if functions have completed.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The message_id that is associated with the function calls"
                    },
                    ["auto_check_interval_seconds"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Set this to zero; Unless the user has requested an auto check. " +
                                      "If they request an auto check then set to 60 seconds or above to setup periodic auto-checks " +
                                      "on the functions status. Warning auto check will use a lot of tokens, only use if requested " +
                                      "and warn the user. To cancel a running auto check set this to -1"
                    }
                },
                Required = new List<string> { "message_id", "auto_check_interval_seconds" }
            }
        };
    }

    public static FunctionDefinition BuildCancelFunctions()
    {
        return new FunctionDefinition
        {
            Name = "cancel_functions",
            Description = "Cancel a function that has not yet completed. It will attempt to halt a running function.It will have no effect on a completed function and will not undo the actions that a function has taken.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The message_id that is associated with the function calls"
                    }
                },
                Required = new List<string> { "message_id" }
            }
        };
    }

    public static FunctionDefinition BuildGetAgentsFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_agents",
            Description = "Retrieve a list of monitoring agent details. Call this to give the user a list of agents to choose from. Note the agents with the users email address in the strings are the user's local agents used for local network tasks. The other agents (Scanner - EU etc.) are internet based agents. If a local agent is not available direct the user to install any of the agents from this page : https://freenetworkmonitor.click/download ",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["detail_response"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Will this function return all agent details. Set to false if only the agent location and function calling capabilities are required. Set to true for full agent details."
                    }
                },
                Required = new List<string> { "detail_response" }
            }
        };
    }

    public static FunctionDefinition BuildRunBusyboxFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_busybox_command",
            Description = "Run BusyBox commands for local network analysis. Key use cases:\n" +
                          "1. Interface status: 'ifconfig eth0' | 'ip addr show'\n" +
                          "2. Connectivity testing: 'ping -c 4 192.168.1.1' | 'traceroute 10.0.0.5'\n" +
                          "3. Network configuration: 'netstat -r' | 'ip route list'\n" +
                          "4. DNS validation: 'nslookup gateway.local' | 'dig +short myip.opendns.com'\n" +
                          "5. ARP analysis: 'arp -a' | 'ip neigh show'",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["command"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "BusyBox network diagnostic command. Examples:\n" +
                                      "- Show all interfaces: 'ip -br addr'\n" +
                                      "- Ping default gateway: 'ping -c 5 $(ip route | awk '/default/ {print $3}')'\n" +
                                      "- Trace route to DNS server: 'traceroute 8.8.8.8'"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Network segment identifier. Examples: 'gateway-node', 'branch-office-switch', 'main-router'"
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Output line limit. Example: 20 lines for 'ip addr show' output"
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Paginate large outputs. Example: Page 2 of routing table ('netstat -r') results"
                    }
                },
                Required = new List<string> { "command" }
            }
        };
    }
}

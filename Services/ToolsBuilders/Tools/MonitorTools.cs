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

public class MonitorTools
{
    public static FunctionDefinition BuildAddHostFunction()
    {
        return new FunctionDefinition
        {
            Name = "add_host",
            Description = "Add a new host to be monitored. This function allows you to specify the host address and various monitoring options. For example, to add a host with address 'example.com' and monitor it using the HTTP endpoint, you would specify {'address': 'example.com', 'endpoint': 'http'}. This will set up monitoring for the specified host using the selected endpoint type.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["detail_response"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Set to true if you want the function to echo all the values set. The default is false for a faster response."
                    },
                    ["address"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "[REQUIRED] The host address to be monitored. This is a required field."
                    },
                    ["endpoint"] = new PropertyDefinition
                    {
                        Type = "string",
                        Enum = new List<string>
                        {
        "quantum",
        "http",
        "https",
        "httphtml",
        "httpfull",
        "sitehash",
        "icmp",
        "dns",
        "smtp",
        "rawconnect",
        "nmap",
        "nmapvuln",
        "crawlsite",
        "dailycrawl",
        "dailyhugkeepalive"
    },
                        Description = "The endpoint type for monitoring. Optional field. Endpoint types include: 'quantum' (a quantum-safe encryption test), 'http' (website ping), 'https' (SSL certificate check), 'httphtml' (loads only the HTML of a website), 'httpfull' (loads full website content including JavaScript), 'sitehash' (loads and hashes rendered website content to detect changes), 'icmp' (host ping), 'dns' (DNS lookup), 'smtp' (email server HELO message confirmation), 'rawconnect' (low-level raw socket connection), 'nmap' (service scan using Nmap), 'nmapvuln' (vulnerability scan using Nmap scripts), 'crawlsite' (traffic generator that crawls a site), 'dailycrawl' (once-daily low-traffic site crawl), 'dailyhugkeepalive' (once-daily trafic generator for a Hugging Face space to keep it alive), 'hugwake' (wake up a Hugging Face space by clicking the restart button if the space is sleeping)."
                    },

                    ["port"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "The port of the service being monitored. Optional field. If not specified, it defaults to the standard port for the endpoint type. For example, the standard port for HTTPS is 443."
                    },
                    ["timeout"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "The time to wait for a timeout in milliseconds. Optional field. The default is 59000 milliseconds."
                    },
                    ["email"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The user's email address. Do not use this field if the user is logged in; their login email will be used and this field will be ignored. If the user is not logged in, then ask for an email. Alerts are sent to the user's email."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The location of the agent monitoring this host. Optional field. If left blank, an agent location will be assigned automatically."
                    }
                },
                Required = new List<string> { "address" }
            }
        };
    }

    public static FunctionDefinition BuildEditHostFunction()
    {
        return new FunctionDefinition
        {
            Name = "edit_host",
            Description = "Edit or Delete a existing host's monitoring configuration. This function allows you to modify the monitoring settings of a host that has already been added or delete a host. For example, to edit the host with address 'test.com' and change the endpoint to 'icmp', you would specify {'address':'test.com', 'endpoint':'icmp'}. To delete a host {'address':'test.com', 'hidden':'true'}. ",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["detail_response"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Set to true if you want the function to echo all the values set. The default is false."
                    },
                    ["auth_key"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "An authentication key used to authorize the edit action for a user who is not logged in. This key is returned when adding a host for the first time. It should be stored and sent with subsequent edit requests. Optional if the user is logged in."
                    },
                    ["id"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "The host ID used for identifying the host. Optional field. It is obtained when adding a host."
                    },
                    ["enabled"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Whether the host is enabled for monitoring. Optional field."
                    },
                    ["address"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The host address. Optional field."
                    },
                    ["endpoint"] = new PropertyDefinition
                    {
                        Type = "string",
                        Enum = new List<string>
                {
        "quantum",
        "http",
        "https",
        "httphtml",
        "httpfull",
        "sitehash",
        "icmp",
        "dns",
        "smtp",
        "rawconnect",
        "nmap",
        "nmapvuln",
        "crawlsite",
        "dailycrawl",
        "dailyhugkeepalive"
    },
                        Description = "The endpoint type for monitoring. Optional field. Endpoint types include: 'quantum' (a quantum-safe encryption test), 'http' (website ping), 'https' (SSL certificate check), 'httphtml' (loads only the HTML of a website), 'httpfull' (loads full website content including JavaScript), 'sitehash' (loads and hashes rendered website content to detect changes), 'icmp' (host ping), 'dns' (DNS lookup), 'smtp' (email server HELO message confirmation), 'rawconnect' (low-level raw socket connection), 'nmap' (service scan using Nmap), 'nmapvuln' (vulnerability scan using Nmap scripts), 'crawlsite' (traffic generator that crawls a site), 'dailycrawl' (once-daily low-traffic site crawl), 'dailyhugkeepalive' (once-daily trafic generator for a Hugging Face space to keep it alive), 'hugwake' (wake up a Hugging Face space by clicking the restart button if the space is sleeping)."
                    },

                    ["port"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "The port of the service being monitored. Optional field."
                    },
                    ["timeout"] = new PropertyDefinition
                    {
                        Type = "number",
                        Description = "The timeout in milliseconds for the request. Optional field."
                    },
                    ["hidden"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Delete a host by setting to true. Optional field."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The location of the agent monitoring this host. Optional field."
                    }
                }
            }
        };
    }

    public static FunctionDefinition BuildGetHostDataFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_host_data",
            Description = "Retrieve monitoring data for hosts based on specified filters. By default, if no filters are provided (empty object {}), all host data will be returned. Add parameters to filter and restrict the results. Examples:\n" +
                          "- Get all hosts with alerts: {'alert_flag': true}\n" +
                          "- Get latest data for specific host: {'dataset_id': 0, 'address': 'test.com'}\n" +
                          "- Get historical data by time rangeand host id: {'id': 2, 'date_start': '2024-04-11T19:20:00', 'date_end': '2024-04-12T19:20:00'}\n" +
                          "- Paginate through all hosts. Starting at page 1 with 10 hosts on it: {'page_number': 1, 'page_size': 10}\n\n" +
                          "Note: Multiple filters can be combined (AND logic)." +
                          "IMPORTANT: ONLY SET FIELDS THAT YOU ARE FILTERING WITH. For example if you want the latest host data for host with a given address you only need to set the address and dataset_id all other fields are NOT needed. ",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["detail_response"] = new PropertyDefinition { Type = "boolean", Description = "Set to true for comprehensive monitoring data including reponse time statistics, agent location, and other info." },
                    ["dataset_id"] = new PropertyDefinition { Type = "number", Description = "Dataset identifier (0 = latest data). For historical data, set to null and specify date range." },
                    ["id"] = new PropertyDefinition { Type = "number", Description = "Filter by host ID" },
                    ["address"] = new PropertyDefinition { Type = "string", Description = "Filter by host address (supports partial matchesa and wildcards * and ?)" },
                    ["email"] = new PropertyDefinition { Type = "string", Description = "Filter by associated email" },
                    ["enabled"] = new PropertyDefinition { Type = "boolean", Description = "Filter by enabled status" },
                    ["port"] = new PropertyDefinition { Type = "number", Description = "Filter by port number" },
                    ["endpoint"] = new PropertyDefinition { Type = "string", Description = "Filter by endpoint type" },
                    ["alert_sent"] = new PropertyDefinition { Type = "boolean", Description = "Filter by alert sent status" },
                    ["alert_flag"] = new PropertyDefinition { Type = "boolean", Description = "Filter by alert flag status" },
                    ["date_start"] = new PropertyDefinition { Type = "string", Description = "Start time for historical data filtering. Requires date_end. Format: 'YYYY-MM-DDTHH:MM:SS'." },
                    ["date_end"] = new PropertyDefinition { Type = "string", Description = "End time for historical data filtering. Format: 'YYYY-MM-DDTHH:MM:SS'." },
                    ["page_number"] = new PropertyDefinition { Type = "number", Description = "Pagination: page number (1-based). Use with page_size for large datasets." },
                    ["page_size"] = new PropertyDefinition { Type = "number", Description = "Pagination: results per page (default=4)." },
                    ["agent_location"] = new PropertyDefinition { Type = "string", Description = "Filter by agent location" }
                }
            }
        };
    }

    public static FunctionDefinition BuildGetHostListFunction()
    {
        return new FunctionDefinition
        {
            Name = "get_host_list",
            Description = "Retrieve a list of monitored hosts and their configurations based on specified filters. By default, if no filters are provided (empty object {}), all hosts will be returned. Add parameters to filter and restrict the results. Examples:\n" +
                          "- Get all hosts with '.com' addresses: {'address': '.com'}\n" +
                          "- Get only DNS endpoint hosts: {'endpoint': 'dns'}\n" +
                          "- Get enabled hosts from specific location: {'enabled': true, 'agent_location': 'London - UK'}\n" +
                          "- Paginate through all hosts, show page 1 with 10 hosts on it: {'page_number': 1, 'page_size': 10}\n\n" +
                          "Note: Multiple filters can be combined (AND logic). Leaving a filter out means that field won't be used to restrict results." +
                          "IMPORTANT: ONLY SET FIELDS THAT YOU ARE FILTERING WITH. For example if you want the latest host config for host with a given address you only need to set the address all other fields are NOT needed. ",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["detail_response"] = new PropertyDefinition { Type = "boolean", Description = "Set to true to include full configuration details (beyond just ID and address)." },
                    ["id"] = new PropertyDefinition { Type = "number", Description = "Filter by host ID" },
                    ["address"] = new PropertyDefinition { Type = "string", Description = "Filter by host address (supports partial matchesa and wildcards * and ?)" },
                    ["email"] = new PropertyDefinition { Type = "string", Description = "Filter by associated email" },
                    ["enabled"] = new PropertyDefinition { Type = "boolean", Description = "Filter by enabled status" },
                    ["port"] = new PropertyDefinition { Type = "number", Description = "Filter by port number" },
                    ["endpoint"] = new PropertyDefinition { Type = "string", Description = "Filter by endpoint type (e.g., 'http', 'dns')" },
                    ["page_number"] = new PropertyDefinition { Type = "number", Description = "Pagination: page number (1-based). Use with page_size for large result sets." },
                    ["page_size"] = new PropertyDefinition { Type = "number", Description = "Pagination: results per page (default=4)." },
                    ["agent_location"] = new PropertyDefinition { Type = "string", Description = "Filter by agent location" }
                }
            }
        };
    }
}

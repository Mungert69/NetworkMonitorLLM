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
        return new FunctionDefinitionBuilder(
            "add_host",
            "Add a new host to be monitored. This function allows you to specify the host address and various monitoring options. For example, to add a host with address 'example.com' and monitor it using the HTTP endpoint, you would specify {'address': 'example.com', 'endpoint': 'http'}. This will set up monitoring for the specified host using the selected endpoint type.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Set to true if you want the function to echo all the values set. The default is false for a faster response."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "[REQUIRED] The host address to be monitored. This is a required field."))
        .AddParameter("endpoint", PropertyDefinition.DefineEnum(
            new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect" },
            "The endpoint type for monitoring. Optional field. Endpoint types include: 'quantum' (a quantum-safe encryption test), 'http' (website ping), 'https' (SSL certificate check), 'httphtml' (loads only the HTML of a website), 'icmp' (host ping), 'dns' (DNS lookup), 'smtp' (email server HELO message confirmation), 'rawconnect' (low-level raw socket connection)."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "The port of the service being monitored. Optional field. If not specified, it defaults to the standard port for the endpoint type. For example, the standard port for HTTPS is 443."))
        .AddParameter("timeout", PropertyDefinition.DefineNumber(
            "The time to wait for a timeout in milliseconds. Optional field. The default is 59000 milliseconds."))
        .AddParameter("email", PropertyDefinition.DefineString(
            "The user's email address. Do not use this field if the user is logged in; their login email will be used and this field will be ignored. If the user is not logged in, then ask for an email. Alerts are sent to the user's email."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "The location of the agent monitoring this host. Optional field. If left blank, an agent location will be assigned automatically."))
        .Validate()
        .Build();
    }

    public static FunctionDefinition BuildEditHostFunction()
    {
        return new FunctionDefinitionBuilder(
            "edit_host",
            "Edit an existing host's monitoring configuration. This function allows you to modify the monitoring settings of a host that has already been added. For example, to edit the host with address 'test.com' and change the endpoint to 'icmp', you would specify {'address':'test.com', 'endpoint':'icmp'}. You can update various parameters such as the endpoint type, port, timeout, and more.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Set to true if you want the function to echo all the values set. The default is false."))
        .AddParameter("auth_key", PropertyDefinition.DefineString(
            "An authentication key used to authorize the edit action for a user who is not logged in. This key is returned when adding a host for the first time. It should be stored and sent with subsequent edit requests. Optional if the user is logged in."))
        .AddParameter("id", PropertyDefinition.DefineNumber(
            "The host ID used for identifying the host. Optional field. It is obtained when adding a host."))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean(
            "Whether the host is enabled for monitoring. Optional field."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "The host address. Optional field."))
        .AddParameter("endpoint", PropertyDefinition.DefineEnum(
            new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect" },
            "The endpoint type for monitoring. Optional field. Endpoint types include: 'quantum', 'http', 'https', 'httphtml', 'icmp', 'dns', 'smtp', 'rawconnect'."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "The port of the service being monitored. Optional field."))
        .AddParameter("timeout", PropertyDefinition.DefineNumber(
            "The timeout in milliseconds for the request. Optional field."))
        .AddParameter("hidden", PropertyDefinition.DefineBoolean(
            "If set to true, the host will be hidden, effectively removing it from future monitoring. Optional field."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "The location of the agent monitoring this host. Optional field."))
        .Validate()
        .Build();
    }

    public static FunctionDefinition BuildGetHostDataFunction()
    {
        return new FunctionDefinitionBuilder(
            "get_host_data",
            "Retrieve monitoring data for hosts. This function allows you to obtain data related to the monitoring of hosts. For example, to get the latest data for a host with address 'test.com', you would specify {'dataset_id': 0, 'address': 'test.com'}. To get data for a host with ID 2 between specific dates, you would specify {'id': 2, 'date_start': '2024-04-11T19:20:00', 'date_end': '2024-04-12T19:20:00'}. You can also filter hosts that are flagged with an alert by specifying {'alert_flag': true}. When using pagination, stop incrementing 'page_number' when no more data is found.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Set to true if you want the function to provide all monitoring data for hosts, including extra response statistics or agent location. Setting it to true may slow down the processing speed."))
        .AddParameter("dataset_id", PropertyDefinition.DefineNumber(
            "Return a set of statistical data. Data is arranged in 6-hour datasets. Set 'dataset_id' to 0 for the latest data. To view historic data, set 'dataset_id' to null and select a date range with 'date_start' and 'date_end'."))
        .AddParameter("id", PropertyDefinition.DefineNumber(
            "Return data for the host with this ID. Optional field."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "Return data for the host with this address. Optional field."))
        .AddParameter("email", PropertyDefinition.DefineString(
            "Return data for hosts associated with this email. Optional field."))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean(
            "Return data for hosts with this enabled status. Optional field."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "Return data for the host with this port. Optional field."))
        .AddParameter("endpoint", PropertyDefinition.DefineString(
            "Return data for hosts with this endpoint type. Optional field."))
        .AddParameter("alert_sent", PropertyDefinition.DefineBoolean(
            "Return data for hosts that have sent a down alert. Optional field."))
        .AddParameter("alert_flag", PropertyDefinition.DefineBoolean(
            "Return data for hosts that have an alert flag set. This can be used to retrieve hosts that are up or down. Optional field."))
        .AddParameter("date_start", PropertyDefinition.DefineString(
            "The start time to filter data from. Used with 'date_end' to define a time range. Optional field."))
        .AddParameter("date_end", PropertyDefinition.DefineString(
            "The end time to filter data up to. Optional field."))
        .AddParameter("page_number", PropertyDefinition.DefineNumber(
            "The current page of paginated results. Starts from 1. Use this when retrieving large datasets incrementally."))
        .AddParameter("page_size", PropertyDefinition.DefineNumber(
            "The maximum number of entries to retrieve per page. The default is 4."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "The location of the agent monitoring this host. Optional field."))
        .Validate()
        .Build();
    }

    public static FunctionDefinition BuildGetHostListFunction()
    {
        return new FunctionDefinitionBuilder(
            "get_host_list",
            "Retrieve a list of monitored hosts and their configurations. This function allows you to obtain information about the hosts being monitored. For example, to filter hosts by address containing '.com', you would specify {'address': '.com'}. To filter hosts with a 'dns' endpoint, you would specify {'endpoint': 'dns'}.")
        .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
            "Set to true if you require more than the host's address and ID. This will provide additional configuration details."))
        .AddParameter("id", PropertyDefinition.DefineNumber(
            "Return configuration for the host with this ID. Optional field."))
        .AddParameter("address", PropertyDefinition.DefineString(
            "Return configuration for the host with this address. Optional field."))
        .AddParameter("email", PropertyDefinition.DefineString(
            "Return configurations for hosts associated with this email. Optional field."))
        .AddParameter("enabled", PropertyDefinition.DefineBoolean(
            "Return configurations for hosts with this enabled status. Optional field."))
        .AddParameter("port", PropertyDefinition.DefineNumber(
            "Return configurations for hosts with this port. Optional field."))
        .AddParameter("endpoint", PropertyDefinition.DefineString(
            "Return configurations for hosts with this endpoint type. Optional field."))
        .AddParameter("page_number", PropertyDefinition.DefineNumber(
            "The current page of paginated results. Starts from 1. Use this when retrieving large datasets incrementally."))
        .AddParameter("page_size", PropertyDefinition.DefineNumber(
            "The maximum number of host configurations to retrieve per page. The default is 4."))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "The location of the agent monitoring these hosts. Optional field."))
        .Validate()
        .Build();
    }

}

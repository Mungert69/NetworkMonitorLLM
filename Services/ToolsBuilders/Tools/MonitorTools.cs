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
public class MonitorTools{
 public static FunctionDefinition BuildAddHostFunction()
        {
            return new FunctionDefinitionBuilder(
                "add_host",
                "Add a new host to be monitored. Example: To monitor 'https://example.com' website: {'address':'https://example.com','endpoint':'http'}. For vulnerability scans: {'address':'192.168.1.5','endpoint':'nmapvuln'}.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
                "Return full configuration details. Default: false (faster response)."))
            .AddParameter("address", PropertyDefinition.DefineString(
                "[REQUIRED] Host address (IP/domain). Examples: '10.0.0.1', 'app.prod'."))
            .AddParameter("endpoint", PropertyDefinition.DefineEnum(
                new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect", "nmapvuln", "nmap", "crawlsite" },
                "Monitoring type. quantum=quantum-safe encryption test, http=website connection test on port 443, https=SSL certificate check only, httphtml=HTML load, icmp=host ping, dns=DNS lookup, smtp=email HELO, rawconnect=raw socket, nmapvuln=Nmap vuln scan, nmap=service scan, crawlsite=Chrome-based crawl. Example to test if website https://example.com use http as the endpoint"))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Service port. Only set if you want to use a non standard port."))
            .AddParameter("timeout", PropertyDefinition.DefineNumber(
                "Timeout in milliseconds. Default: 59000 (~1 minute)."))
            .AddParameter("email", PropertyDefinition.DefineString(
                "[Non-logged-in users only] Alert email. Ignored if authenticated."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Monitoring agent (e.g., 'Berlin - Germany'). Auto-assigned if blank."))
            .Validate()
            .Build();
        }

        public static FunctionDefinition BuildEditHostFunction()
        {
            return new FunctionDefinitionBuilder(
                "edit_host",
                "Edit a host's monitoring configuration. Example: Disable host ID 15: {'id':15,'enabled':false}. Change to ICMP: {'address':'legacy-app','endpoint':'icmp'}.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
                "Return full updated configuration. Default: false."))
            .AddParameter("auth_key", PropertyDefinition.DefineString(
                "[Required if not logged in] Auth key from initial host creation."))
            .AddParameter("id", PropertyDefinition.DefineNumber(
                "Host ID (from get_host_list). Example: 15."))
            .AddParameter("enabled", PropertyDefinition.DefineBoolean(
                "Enable/disable monitoring. Default: true."))
            .AddParameter("address", PropertyDefinition.DefineString(
                "Update host address (e.g., 'new-app.prod')."))
            .AddParameter("endpoint", PropertyDefinition.DefineEnum(
                new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect", "nmapvuln", "nmap", "crawlsite" },
                "Monitoring type. quantum=quantum-safe encryption test, http=website connection test on port 443, https=SSL certificate check only, httphtml=HTML load, icmp=host ping, dns=DNS lookup, smtp=email HELO, rawconnect=raw socket, nmapvuln=Nmap vuln scan, nmap=service scan, crawlsite=Chrome-based crawl. Example to test if website https://example.com use http as the endpoint"))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Update service port (e.g., 8080 for non-standard HTTP)."))
            .AddParameter("timeout", PropertyDefinition.DefineNumber(
                "Adjust timeout (ms). Default: 59000."))
            .AddParameter("hidden", PropertyDefinition.DefineBoolean(
                "Hide host (soft delete). Default: false."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Reassign monitoring agent (e.g., 'London - UK')."))
            .Validate()
            .Build();
        }

        public static FunctionDefinition BuildGetHostDataFunction()
        {
            return new FunctionDefinitionBuilder(
                "get_host_data",
                "Retrieve host monitoring data with optional filters. Use this to get the actual host monitoring data. In general you would only filter by address and then add fields to apply additional filters")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
                "Include full metrics (response times/headers). Default: false."))
            .AddParameter("dataset_id", PropertyDefinition.DefineNumber(
                "Get data within a dataset (0=latest). Do not set this if you set date_start or date_end"))
            .AddParameter("id", PropertyDefinition.DefineNumber(
                "Filter by host id. In general only use this if only one host with a given id is required"))
            .AddParameter("address", PropertyDefinition.DefineString(
                "Fitler by host address. You can use wildcard filters (e.g., 'example*'). Supports * and ? wildcards."))
            .AddParameter("email", PropertyDefinition.DefineString(
                "Filter by alert recipient email."))
            .AddParameter("enabled", PropertyDefinition.DefineBoolean(
                "Filter by Active/inactive hosts. Default: true."))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Filter by port (e.g., 443)."))
            .AddParameter("endpoint", PropertyDefinition.DefineString(
                "Filter by endpoint type"))
            .AddParameter("alert_sent", PropertyDefinition.DefineBoolean(
                "Filter by hosts that have had an email alert sent))
            .AddParameter("alert_flag", PropertyDefinition.DefineBoolean(
                "Filter by Hosts in alert state true (host down) false (host down)."))
            .AddParameter("date_start", PropertyDefinition.DefineString(
                "Filter by ISO start time (e.g., '2024-05-01T00:00:00')."))
            .AddParameter("date_end", PropertyDefinition.DefineString(
                "Fitler by ISO end time."))
            .AddParameter("page_size", PropertyDefinition.DefineNumber(
                "Results per page. Default: 4."))
            .AddParameter("page_number", PropertyDefinition.DefineNumber(
                "Pagination page. Default: 1."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Filter by agent location. In general leave this field out unless you want Filter by agent location"))
            .Validate()
            .Build();
        }

        public static FunctionDefinition BuildGetHostListFunction()
        {
            return new FunctionDefinitionBuilder(
                "get_host_list",
                "List monitored host configuration. Only use this to show host monitoring configuration.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
                "Include full config (tags/thresholds). Default: false."))
            .AddParameter("id", PropertyDefinition.DefineNumber(
                "Host ID (e.g., 15)."))
            .AddParameter("address", PropertyDefinition.DefineString(
                "Fitler by host address. You can use wildcard filters (e.g., '*.com'). Supports * and ? wildcards."))
            .AddParameter("email", PropertyDefinition.DefineString(
                "Filter by contact email."))
            .AddParameter("enabled", PropertyDefinition.DefineBoolean(
                "Filter by Active/inactive hosts. Default: true."))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Filter by port (e.g., 443)."))
            .AddParameter("endpoint", PropertyDefinition.DefineString(
                "Filter by endpoint (e.g., 'dns')."))
            .AddParameter("page_size", PropertyDefinition.DefineNumber(
                "Results per page. Default: 10."))
            .AddParameter("page_number", PropertyDefinition.DefineNumber(
                "Pagination page. Default: 1."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Filter by agent locatoin. In general leave this field out unless you want Filter by agent location"))
            .Validate()
            .Build();
        }

}

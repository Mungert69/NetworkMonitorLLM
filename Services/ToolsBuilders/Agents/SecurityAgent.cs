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

public class SecurityAgent
{

    public static FunctionDefinition BuildSecurityBasicAgent()
    {
        return new FunctionDefinitionBuilder(
                "call_security_basic_agent",
                "Call the security agent to perform a basic security assessment on the target ")
                .AddParameter(
                    "target",
                    PropertyDefinition.DefineString(
                        "The target to scan - can be an IP address (e.g., '192.168.1.1'), " +
                        "IP range ('192.168.1.0/24'), domain name ('example.com'), " +
                        "or hostname. Validate the target with the user if ambiguous."))
                .Validate()
                .Build();
    }

  

}
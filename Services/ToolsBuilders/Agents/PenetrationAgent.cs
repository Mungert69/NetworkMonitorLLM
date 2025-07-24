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

public class PenetrationAgent
{

    public static FunctionDefinition BuildPenetrationAgent()
    {
        return new FunctionDefinitionBuilder(
                "call_penetration_flow",
                "Penetration Flow. Use the Penetration flow to start a multi-step flow that performs a penetration test on the specified target. " +
                "Only call this function if the user clearly indicates they want to initiate a penetration flow ." +
                "The result from this function call will be professionally presented report. Give the user the report without any modifications.")
                    .AddParameter(
                    "target",
                    PropertyDefinition.DefineString(
                        "The target to scan - can be an IP address (e.g., '192.168.1.1'), " +
                        "IP range ('192.168.1.0/24'), domain name ('example.com'), " +
                        "or hostname. Validate the target with the user if ambiguous."))
                     .AddParameter(
                    "agent_location",
                    PropertyDefinition.DefineString(
                        "The location of the agent. This is required"))
                .Validate()
                .Build();
    }



}
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

public class CmdProcessorBuilderAgent
{

    public static FunctionDefinition BuildCmdProcessorBuilderAgent()
    {
        return new FunctionDefinitionBuilder(
                "call_cmd_processor_builder_flow",
                "Cmd Processor Builder Expert. Use Cmd Processor Builder flow expert to start a multi-step flow that creates or updates a cmd processor and performs a test on it to confirm that it works. " +
                "Only call this function if the user clearly indicates they want to initiate a cmd processor builder flow ." +
                "The result from this function call will be professionally presented report. Give the user the report without any modifications.")
                    .AddParameter(
                    "user_input",
                    PropertyDefinition.DefineString(
                        "Required: The desired behavior of the cmd processor "))
                         .AddParameter(
                    "agent_location",
                    PropertyDefinition.DefineString(
                        "The location of the agent."))
                         .AddParameter(
                    "cmd_processor_type",
                    PropertyDefinition.DefineString(
                        "Required: The cmd processor name. Do not to include the word CmdProcessor in the name. This is forbibben and will cause the cmd processor to fail."))
                .Validate()
                .Build();
    }



}
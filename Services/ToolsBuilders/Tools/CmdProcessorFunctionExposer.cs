using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
namespace NetworkMonitor.LLM.Services;

public static class CmdProcessorFunctionExposer
{
    // Template for all dynamic processor functions (swap/cp_*) exposed to the LLM
    public static FunctionDefinition BuildCmdProcessorFunction(CmdProcessorFunctionSpec spec)
    {
        var functionName = $"cp_{spec.Name}";
        var doc = spec.Description ?? $"Run the '{spec.Name}' cmd processor on a specified agent.";

        var builder = new FunctionDefinitionBuilder(functionName, doc);

        if (spec.Parameters != null)
        {
            foreach (var p in spec.Parameters)
                builder.AddParameter(p.Name, MapTypeToPropertyDef(p.Type, p.Description));
        }

        return builder.Validate().Build();
    }
    private static PropertyDefinition MapTypeToPropertyDef(string type, string? description)
    {
        switch (type.ToLowerInvariant())
        {
            case "string":
                return PropertyDefinition.DefineString(description ?? "");
            case "integer":
            case "int":
                return PropertyDefinition.DefineInteger(description ?? "");
            case "boolean":
            case "bool":
                return PropertyDefinition.DefineBoolean(description ?? "");
            case "number":
            case "float":
            case "double":
                return PropertyDefinition.DefineNumber(description ?? "");
            // Add more types if your LLM tool supports them
            default:
                throw new ArgumentException($"Unknown parameter type '{type}'");
        }
    }


}

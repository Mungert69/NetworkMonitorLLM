using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Objects;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public static class CmdProcessorFunctionExposer
{
    // Template for all dynamic processor functions (swap/cp_*) exposed to the LLM
    public static FunctionDefinition BuildCmdProcessorFunction(CmdProcessorFunctionSpec spec)
    {
        var functionName = spec.Name;
        var doc = spec.Description ?? $"Run the '{spec.Name}' cmd processor on a specified agent.";

        var builder = new FunctionDefinitionBuilder(functionName, doc);
        var requiredParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (spec.Parameters != null)
        {
            foreach (var p in spec.Parameters)
            {
                builder.AddParameter(p.Name, MapTypeToPropertyDef(p.Type, p.Description));

                if (IsParameterRequired(p))
                {
                    requiredParams.Add(p.Name);
                }
            }
        }

        // merge explicit Required list from spec
        if (spec.Required != null)
        {
            foreach (var req in spec.Required)
            {
                if (!string.IsNullOrWhiteSpace(req))
                    requiredParams.Add(req);
            }
        }

        var fd = builder.Validate().Build();

        // Ensure schema type is "object"
        if (fd.Parameters != null)
        {
            if (string.IsNullOrEmpty(fd.Parameters.Type))
                fd.Parameters.Type = "object";

            if (requiredParams.Count > 0)
                fd.Parameters.Required = new List<string>(requiredParams);
        }

        return fd;
    }

    private static bool IsParameterRequired(CmdProcessorParamSpec p)
    {
        if (p.Required)
            return true;

        if (!string.IsNullOrEmpty(p.Description) &&
            p.Description.Contains("[REQUIRED]", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
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
            default:
                throw new ArgumentException($"Unknown parameter type '{type}'");
        }
    }
}

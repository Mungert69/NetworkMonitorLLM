using System.Collections.Generic;
using System.IO;
using System;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
namespace NetworkMonitor.LLM.Services;
public class ToolDefinitionParser
{
    public static List<ToolDefinition> ParseFromJson(string json)
    {
        var tools = new List<ToolDefinition>();
        var jArray = JArray.Parse(json);

        foreach (var item in jArray)
        {
            var tool = new ToolDefinition
            {
                Type = item["type"]?.ToString(),
                Function = ParseFunctionDefinition(item["function"] as JObject)
            };
            tools.Add(tool);
        }

        return tools;
    }

    private static FunctionDefinition ParseFunctionDefinition(JObject functionJson)
    {
        var builder = new FunctionDefinitionBuilder(
            functionJson["name"]?.ToString(),
            functionJson["description"]?.ToString()
        );

        var parameters = functionJson["parameters"]?["properties"] as JObject;
        if (parameters != null)
        {
            foreach (var param in parameters.Properties())
            {
                var prop = param.Value as JObject;
                var paramType = prop?["type"]?.ToString().ToLower();
                var description = prop?["description"]?.ToString();

                switch (paramType)
                {
                    case "string":
                        builder.AddParameter(param.Name, PropertyDefinition.DefineString(description));
                        break;
                    case "integer":
                        builder.AddParameter(param.Name, PropertyDefinition.DefineInteger(description));
                        break;
                    case "boolean":
                        builder.AddParameter(param.Name, PropertyDefinition.DefineBoolean(description));
                        break;
                    case "number":
                        builder.AddParameter(param.Name, PropertyDefinition.DefineNumber(description));
                        break;
                    case "array":
                        // Define the type of items in the array
                        var itemType = prop?["items"]?["type"]?.ToString().ToLower();
                        var itemDefinition = itemType switch
                        {
                            "string" => PropertyDefinition.DefineString("Item in the array"),
                            "number" => PropertyDefinition.DefineNumber("Item in the array"),
                            "integer" => PropertyDefinition.DefineInteger("Item in the array"),
                            "boolean" => PropertyDefinition.DefineBoolean("Item in the array"),
                            _ => throw new ArgumentException($"Unsupported array item type: {itemType}")
                        };
                        builder.AddParameter(param.Name, PropertyDefinition.DefineArray(itemDefinition));
                        break;
                    default:
                        throw new ArgumentException($"Unsupported parameter type: {paramType}");
                }
            }
        }

        return builder.Validate().Build();
    }
}
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
            if (item["type"] != null && item["function"]!=null)
            {
                var tool = new ToolDefinition
                {
                    Type = item["type"]?.ToString() ?? "",
                    Function = ParseFunctionDefinition(item["function"] as JObject)
                };
                tools.Add(tool);
            }
        }

        return tools;
    }

    private static FunctionDefinition ParseFunctionDefinition(JObject? functionJson)
    {
        if (functionJson == null)
        {
            return new FunctionDefinitionBuilder("default_name", "No description available").Validate().Build();
        }

        var builder = new FunctionDefinitionBuilder(
            functionJson["name"]?.ToString() ?? "func_name",
            functionJson["description"]?.ToString() ?? "No description available"
        );

        var parameters = functionJson["parameters"]?["properties"] as JObject;
        if (parameters != null)
        {
            foreach (var param in parameters.Properties())
            {
                var prop = param.Value as JObject;
                var paramType = prop?["type"]?.ToString()?.ToLower();
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
                        var itemType = prop?["items"]?["type"]?.ToString()?.ToLower();
                        var itemDefinition = itemType switch
                        {
                            "string" => PropertyDefinition.DefineString("Item in the array"),
                            "number" => PropertyDefinition.DefineNumber("Item in the array"),
                            "integer" => PropertyDefinition.DefineInteger("Item in the array"),
                            "boolean" => PropertyDefinition.DefineBoolean("Item in the array"),
                            "object" => ParseObjectDefinition(prop?["items"] as JObject),
                            _ => throw new ArgumentException($"Unsupported array item type: {itemType}")
                        };
                        builder.AddParameter(param.Name, PropertyDefinition.DefineArray(itemDefinition));
                        break;
                    case "object":
                        builder.AddParameter(param.Name, ParseObjectDefinition(prop));
                        break;
                    case "null":
                        builder.AddParameter(param.Name, PropertyDefinition.DefineNull(description));
                        break;
                    default:
                        throw new ArgumentException($"Unsupported parameter type: {paramType}");
                }
            }
        }

        return builder.Validate().Build();
    }

    private static PropertyDefinition ParseObjectDefinition(JObject? objectJson)
    {
        if (objectJson == null)
        {
            return new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>(),
                Required = new List<string>()
            };
        }

        var properties = new Dictionary<string, PropertyDefinition>();
        var required = new List<string>();

        var props = objectJson["properties"] as JObject;
        if (props != null)
        {
            foreach (var prop in props.Properties())
            {
                var propDef = prop.Value as JObject;
                var propType = propDef?["type"]?.ToString()?.ToLower();
                var description = propDef?["description"]?.ToString();

                switch (propType)
                {
                    case "string":
                        properties[prop.Name] = PropertyDefinition.DefineString(description);
                        break;
                    case "integer":
                        properties[prop.Name] = PropertyDefinition.DefineInteger(description);
                        break;
                    case "boolean":
                        properties[prop.Name] = PropertyDefinition.DefineBoolean(description);
                        break;
                    case "number":
                        properties[prop.Name] = PropertyDefinition.DefineNumber(description);
                        break;
                    case "array":
                        var itemType = propDef?["items"]?["type"]?.ToString()?.ToLower();
                        var itemDefinition = itemType switch
                        {
                            "string" => PropertyDefinition.DefineString("Item in the array"),
                            "number" => PropertyDefinition.DefineNumber("Item in the array"),
                            "integer" => PropertyDefinition.DefineInteger("Item in the array"),
                            "boolean" => PropertyDefinition.DefineBoolean("Item in the array"),
                            "object" => ParseObjectDefinition(propDef?["items"] as JObject),
                            _ => throw new ArgumentException($"Unsupported array item type: {itemType}")
                        };
                        properties[prop.Name] = PropertyDefinition.DefineArray(itemDefinition);
                        break;
                    case "object":
                        properties[prop.Name] = ParseObjectDefinition(propDef);
                        break;
                    case "null":
                        properties[prop.Name] = PropertyDefinition.DefineNull(description);
                        break;
                    default:
                        throw new ArgumentException($"Unsupported property type: {propType}");
                }
            }
        }

        var requiredProps = objectJson["required"] as JArray;
        if (requiredProps != null)
        {
            foreach (var req in requiredProps)
            {
                required.Add(req.ToString());
            }
        }

        return new PropertyDefinition
        {
            Type = "object",
            Properties = properties,
            Required = required,
            AdditionalProperties = objectJson["additionalProperties"]?.ToObject<bool?>()
        };
    }

}
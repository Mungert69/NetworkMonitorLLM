using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;
using NetworkMonitor.Objects.Factory;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.Tokenizer.GPT3;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
public static class JsonToolsBuilder
{
    public static string BuildToolsJson(List<ToolDefinition> tools)
    {
        var toolJsonList = tools.Select(tool => new
        {
            name = tool.Function.Name,
            description = tool.Function.Description,
            parameters = new
            {
                type = "object",
                properties = tool.Function.Parameters?.Properties?
                    .Where(p => p.Value != null) // Exclude null properties
                    .ToDictionary(
                        param => param.Key,
                        param => new
                        {
                            type = param.Value.Type,
                            description = param.Value.Description
                        }
                    )
            }
        });

        // Serialize to JSON and ignore null values
        return JsonConvert.SerializeObject(toolJsonList, Formatting.Indented, new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        });
    }


}

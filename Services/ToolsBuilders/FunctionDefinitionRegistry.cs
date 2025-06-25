// -------------------------------------------------------------------------
// File: FunctionDefinitionRegistry.cs
// -------------------------------------------------------------------------
using System.Reflection;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using System.Collections.Generic;
using System;
using System.Linq;
using System.Text.Json;
using System.Reflection;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
namespace NetworkMonitor.LLM.Services;

public interface IFunctionDefinitionRegistry
{
    /// <summary>
    /// Serializes the available functions into a JSON catalog.
    /// </summary>
    /// <param name="pretty">If true, formats the JSON with indentation.</param>
    /// <returns>A JSON string containing function id & description pairs.</returns>
    string GetFunctionCatalogJson(bool pretty = true);

    /// <summary>
    /// Tries to resolve a function by its identifier.
    /// </summary>
    /// <param name="id">The function name/key to look up.</param>
    /// <param name="fd">When this method returns, contains the resolved FunctionDefinition if found; otherwise null.</param>
    /// <returns>True if the function was found; otherwise false.</returns>
    bool TryResolve(string id, out FunctionDefinition fd);
}

/// <summary>Scans every *Tools* class, calls each BuildXxxFunction method,
/// and caches the resulting FunctionDefinitions keyed by their name
/// (e.g. "run_nmap").</summary>
public class FunctionDefinitionRegistry : IFunctionDefinitionRegistry
{
    private readonly IRabbitRepo _rabbitRepo;
    private Dictionary<string, FunctionDefinition> _map =
        new(StringComparer.OrdinalIgnoreCase);

    public FunctionDefinitionRegistry(IRabbitRepo rabbitRepo)
    {
        _rabbitRepo = rabbitRepo;
        BuildRegistry();
    }

    private void BuildRegistry()
    {
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            foreach (var type in asm.GetTypes()
                                    .Where(t => t.IsClass &&
                                                t.Name.EndsWith("Tools",
                                                    StringComparison.Ordinal)))
            {
                foreach (var mi in type.GetMethods(BindingFlags.Public |
                                                   BindingFlags.Static)
                                       .Where(m => m.ReturnType ==
                                                   typeof(FunctionDefinition) &&
                                                   m.GetParameters().Length == 0 &&
                                                   m.Name.StartsWith("Build",
                                                      StringComparison.Ordinal)))
                {
                    var fd = (FunctionDefinition)mi.Invoke(obj: null, parameters: null)!;
                    _map[fd.Name] = fd;        // fd.Name == "run_nmap" / "run_openssl"…
                }
            }
        }
    }
    public string GetFunctionCatalogJson(bool pretty = true)
    {
        // 1) Build the JSON payload
        var payload = new
        {
            functions = _map.Values.Select(fd => new
            {
                id = fd.Name,
                description = fd.Description
            })
        };

        var json = JsonSerializer.Serialize(
            payload,
            new JsonSerializerOptions { WriteIndented = pretty });

        // 2) Publish a FunctionRegistryReply over RabbitMQ
        var reply = new FunctionRegistryReply
        {
            CatalogJson = json,
            Success = !string.IsNullOrEmpty(json),
            Message = !string.IsNullOrEmpty(json)
                    ? "Found tool in catalog"
                    : "Could not find tool in catalog"
        };

        // fire-and-forget; if you need to await, make this method async
        _rabbitRepo.PublishAsync<FunctionRegistryReply>("functionRegistryReply", reply);

        // 3) Return the JSON to the caller as before
        return json;
    }
    public bool TryResolve(string id, out FunctionDefinition fd)
        => _map.TryGetValue(id, out fd);
}

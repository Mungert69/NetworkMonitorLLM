// -------------------------------------------------------------------------
// File: FunctionDefinitionRegistry.cs
// -------------------------------------------------------------------------

using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Encodings.Web;
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
    string GetFilteredFunctionCatalogJson(bool pretty = true);

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
    private readonly ILogger _logger;
    private Dictionary<string, FunctionDefinition> _map =
        new(StringComparer.OrdinalIgnoreCase);

    public FunctionDefinitionRegistry(ILogger<FunctionDefinitionRegistry> logger, IRabbitRepo rabbitRepo)
    {
        _rabbitRepo = rabbitRepo;
        _logger = logger;
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
        var payload = new
        {
            functions = _map.Values.Select(fd => new
            {
                id = fd.Name,
                description = fd.Description,
                parameters = fd.Parameters?.Properties != null
                    ? string.Join(",", fd.Parameters.Properties.Select(kvp => kvp.Key))
                    : string.Empty
            })
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = pretty,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping

        };

        var json = JsonSerializer.Serialize(payload, options);

        var reply = new FunctionRegistryReply
        {
            CatalogJson = json ?? string.Empty,
            Success = !string.IsNullOrEmpty(json),
            Message = !string.IsNullOrEmpty(json)
                            ? "Function catalog generated"
                            : "Failed to generate function catalog"
        };
        _rabbitRepo.PublishAsync("functionRegistryReply", reply);

        return json ?? string.Empty;
    }

    public string GetFunctionCatalogFullJson(bool pretty = true)
    {
        var payload = new
        {
            functions = _map.Values.Select(fd => new
            {
                id = fd.Name,
                description = fd.Description,
                parameters = fd.Parameters?.Properties != null
                    ? fd.Parameters.Properties.Select(kvp => new
                        {
                            name = kvp.Key,
                            type = kvp.Value.Type.ToString().ToLower(),         // string | integer | boolean | object | array
                            description = kvp.Value.Description
                        })
                    : Enumerable.Empty<object>()
            })
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = pretty,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping

        };

        var json = JsonSerializer.Serialize(payload, options);

        var reply = new FunctionRegistryReply
        {
            CatalogJson = json,
            Success = !string.IsNullOrEmpty(json),
            Message = !string.IsNullOrEmpty(json)
                            ? "Function catalog generated"
                            : "Failed to generate function catalog"
        };
        _rabbitRepo.PublishAsync("functionRegistryReply", reply);

        return json;
    }

    /// <summary>
    /// Returns a JSON list of functions whose names do NOT end with "_expert".
    /// </summary>
    /// <param name="pretty">If true, formats the JSON with indentation.</param>
    /// <returns>A JSON string containing filtered function id & description pairs.</returns>
    public string GetFilteredFunctionCatalogJson(bool pretty = true)
    {
        var filteredFunctions = _map.Values
            .Where(fd => !fd.Name.EndsWith("_expert", StringComparison.OrdinalIgnoreCase))
            .Select(fd => new
            {
                id = fd.Name,
                description = fd.Description,
                parameters = string.Join(",", fd.Parameters.Properties.Select(kvp => kvp.Key))
            });

        var payload = new
        {
            functions = filteredFunctions
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = pretty,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        var json = JsonSerializer.Serialize(payload, options);

        var reply = new FunctionRegistryReply
        {
            CatalogJson = json ?? string.Empty,
            Success = !string.IsNullOrEmpty(json),
            Message = !string.IsNullOrEmpty(json)
                            ? "Filtered function catalog generated"
                            : "Failed to generate filtered function catalog"
        };
        _rabbitRepo.PublishAsync("functionRegistryReply", reply);

        return json ?? string.Empty;
    }


    public bool TryResolve(string id, out FunctionDefinition fd)
        => _map.TryGetValue(id, out fd);
}

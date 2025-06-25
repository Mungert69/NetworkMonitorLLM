// -------------------------------------------------------------------------
// File: FunctionDefinitionRegistry.cs
// -------------------------------------------------------------------------
using System.Reflection;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using System.Collections.Generic;
using System;
using System;
using System.Linq;          // LINQ helpers used later
using System.Reflection;
namespace NetworkMonitor.LLM.Services;

/// <summary>Scans every *Tools* class, calls each BuildXxxFunction method,
/// and caches the resulting FunctionDefinitions keyed by their name
/// (e.g. "run_nmap").</summary>
public static class FunctionDefinitionRegistry
{
    private static readonly Dictionary<string, FunctionDefinition> _map =
        new(StringComparer.OrdinalIgnoreCase);

    static FunctionDefinitionRegistry()
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

    public static bool TryResolve(string id, out FunctionDefinition fd)
        => _map.TryGetValue(id, out fd);
}

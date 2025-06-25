// -------------------------------------------------------------------------
// File: JsonDrivenToolsBuilder.cs
// -------------------------------------------------------------------------
using NetworkMonitor.Objects.ServiceMessage;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Text.Json;
using NetworkMonitor.Objects;
namespace NetworkMonitor.LLM.Services;

public class JsonDrivenToolsBuilder : ToolsBuilderBase
{
    private readonly ToolBuilderSpec _spec;

    public JsonDrivenToolsBuilder(ToolBuilderSpec spec, IFunctionDefinitionRegistry functionDefinitionRegistry)
    {
        _spec = spec;

        _tools = _spec.Functions
                      .Select(id => {
                          if (!functionDefinitionRegistry.TryResolve(id, out var fd))
                              throw new InvalidOperationException($"Unknown function '{id}'");

                          return new ToolDefinition { Function = fd, Type = "function" };
                      })
                      .ToList();
    }

    public override List<ChatMessage> GetSystemPrompt(
        string currentTime, LLMServiceObj _, string __)
        => new() {
            new ChatMessage {
                Role    = "system",
                Content = _spec.SystemPrompt.Replace("{time}", currentTime)
            }
        };

    public string Id => _spec.Id;
}

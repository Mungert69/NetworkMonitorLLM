// -------------------------------------------------------------------------
// File: ToolBuilderSpec.cs
// -------------------------------------------------------------------------
namespace NetworkMonitor.LLM.Services;

public sealed class ToolBuilderSpec
{
    public required string Id            { get; init; }
    public required string SystemPrompt  { get; init; }
    public required string[] Functions   { get; init; }   // ["run_nmap", ...]
}

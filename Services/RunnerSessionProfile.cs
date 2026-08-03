using System;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public enum SessionPersistenceKind
{
    SharedHistory,
    LocalPersistentContext
}

public sealed record RunnerSessionProfile(SessionPersistenceKind PersistenceKind)
{
    public bool UsesLocalPersistentContext => PersistenceKind == SessionPersistenceKind.LocalPersistentContext;
}

/// <summary>
/// The single place that defines where a runner's durable session state lives.
/// Future local runners are added here rather than adding type checks to the
/// history loading, saving, deletion, and display paths.
/// </summary>
public static class RunnerSessionProfiles
{
    private static readonly RunnerSessionProfile SharedHistory = new(SessionPersistenceKind.SharedHistory);
    private static readonly IReadOnlyDictionary<string, RunnerSessionProfile> Profiles =
        new Dictionary<string, RunnerSessionProfile>(StringComparer.OrdinalIgnoreCase)
        {
            ["TestLLM"] = new(SessionPersistenceKind.LocalPersistentContext)
        };

    public static RunnerSessionProfile For(string? runnerType)
    {
        return !string.IsNullOrWhiteSpace(runnerType) && Profiles.TryGetValue(runnerType, out var profile)
            ? profile
            : SharedHistory;
    }
}

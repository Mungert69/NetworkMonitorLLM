using System;
using System.Collections.Generic;
using System.Linq;

namespace NetworkMonitor.LLM.Services;

public sealed class HistorySequenceState
{
    private readonly List<long> _sequences = new();

    public IReadOnlyList<long> Sequences => _sequences;
    public long NextSequence { get; private set; }

    public void Initialize(IEnumerable<long>? sequences, long nextSequence, int historyCount)
    {
        _sequences.Clear();
        if (sequences != null)
        {
            _sequences.AddRange(sequences);
        }

        if (_sequences.Count != historyCount || _sequences.Distinct().Count() != _sequences.Count)
        {
            _sequences.Clear();
            for (var i = 0; i < historyCount; i++) _sequences.Add(i);
            NextSequence = historyCount;
            return;
        }

        NextSequence = Math.Max(nextSequence, _sequences.Count == 0 ? 0 : _sequences.Max() + 1);
    }

    public void EnsureAligned(int historyCount)
    {
        if (_sequences.Count == historyCount) return;
        Initialize(_sequences, NextSequence, historyCount);
    }

    public void Append(int count)
    {
        for (var i = 0; i < count; i++) _sequences.Add(NextSequence++);
    }

    public long At(int index) => _sequences[index];

    public void Replace(IEnumerable<long> sequences)
    {
        _sequences.Clear();
        _sequences.AddRange(sequences);
        NextSequence = Math.Max(NextSequence, _sequences.Count == 0 ? 0 : _sequences.Max() + 1);
    }
}

public interface IHistorySequenceAwareRunner
{
    void SetHistorySequenceState(HistorySequenceState state);
}

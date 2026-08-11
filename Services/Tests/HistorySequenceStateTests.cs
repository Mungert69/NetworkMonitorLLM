using System.Collections.Generic;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HistorySequenceStateTests
{
    [Fact]
    public void ReplaceAndAppend_PreservesRemainingSequencesAfterTruncation()
    {
        var state = new HistorySequenceState();
        state.Initialize(new List<long> { 0, 1, 2, 3 }, 4, 4);

        state.Replace(new List<long> { 0, 3 });
        state.Append(2);

        Assert.Equal(new long[] { 0, 3, 4, 5 }, state.Sequences);
        Assert.Equal(6, state.NextSequence);
    }

    [Fact]
    public void Initialize_LegacyHistory_AssignsStableSequencesOnce()
    {
        var state = new HistorySequenceState();

        state.Initialize(null, 0, 3);

        Assert.Equal(new long[] { 0, 1, 2 }, state.Sequences);
        Assert.Equal(3, state.NextSequence);
    }

    [Fact]
    public void GetArchivedRanges_CoalescesGapsAndLimitsRenderedRanges()
    {
        var state = new HistorySequenceState();
        state.Initialize(new List<long> { 1, 3, 5, 7, 9 }, 10, 5);

        var archive = state.GetArchivedRanges(3);

        Assert.Equal(new[]
        {
            new HistorySequenceRange(0, 0),
            new HistorySequenceRange(2, 2),
            new HistorySequenceRange(4, 4)
        }, archive.Ranges);
        Assert.True(archive.HasAdditionalRanges);
    }
}

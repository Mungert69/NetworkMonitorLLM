using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class AudioStreamProviderTests
{
    [Fact]
    public async Task QueueAudioStreamBestEffort_EmitsSequencedUrls()
    {
        var emitted = new List<string>();
        var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var responseProcessor = CreateResponseProcessor(emitted, expectedCount: 2, done);
        var logger = new Mock<ILogger>();

        var audioGenerator = new FakeAudioGenerator(async (text, ct) =>
        {
            await Task.Yield();
            return new List<string>
            {
                "https://audio.example.com/a.wav",
                "https://audio.example.com/b.wav"
            };
        });

        var provider = new AudioStreamProvider(audioGenerator, responseProcessor.Object, logger.Object, "TestLLM");
        var serviceObj = new LLMServiceObj
        {
            SessionId = "session-audio-seq",
            RequestSessionId = "request-audio-seq",
            MessageID = "msg-audio-seq"
        };

        provider.QueueAudioStreamBestEffort("hello world", serviceObj);
        await WaitFor(done.Task, TimeSpan.FromSeconds(3));

        Assert.Equal(2, emitted.Count);
        Assert.StartsWith("</audio>https://audio.example.com/a.wav", emitted[0], StringComparison.Ordinal);
        Assert.StartsWith("</audio>https://audio.example.com/b.wav", emitted[1], StringComparison.Ordinal);
        Assert.Contains("stream=msg-audio-seq", emitted[0], StringComparison.Ordinal);
        Assert.Contains("stream=msg-audio-seq", emitted[1], StringComparison.Ordinal);
        Assert.Contains("seq=0", emitted[0], StringComparison.Ordinal);
        Assert.Contains("seq=1", emitted[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task QueueAudioStreamBestEffort_SerializesBySessionKey()
    {
        var emitted = new List<string>();
        var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var responseProcessor = CreateResponseProcessor(emitted, expectedCount: 3, done);
        var logger = new Mock<ILogger>();

        var audioGenerator = new FakeAudioGenerator(async (text, ct) =>
        {
            if (text == "first")
            {
                await Task.Delay(15, ct);
                return new List<string>
                {
                    "https://audio.example.com/first-1.wav",
                    "https://audio.example.com/first-2.wav"
                };
            }

            await Task.Delay(1, ct);
            return new List<string>
            {
                "https://audio.example.com/second-1.wav"
            };
        });

        var provider = new AudioStreamProvider(audioGenerator, responseProcessor.Object, logger.Object, "TestLLM");
        var firstServiceObj = new LLMServiceObj
        {
            SessionId = "same-session",
            MessageID = "msg-first"
        };
        var secondServiceObj = new LLMServiceObj
        {
            SessionId = "same-session",
            MessageID = "msg-second"
        };

        provider.QueueAudioStreamBestEffort("first", firstServiceObj);
        provider.QueueAudioStreamBestEffort("second", secondServiceObj);
        await WaitFor(done.Task, TimeSpan.FromSeconds(3));

        Assert.Equal(3, emitted.Count);
        Assert.Contains("stream=msg-first", emitted[0], StringComparison.Ordinal);
        Assert.Contains("seq=0", emitted[0], StringComparison.Ordinal);
        Assert.Contains("stream=msg-first", emitted[1], StringComparison.Ordinal);
        Assert.Contains("seq=1", emitted[1], StringComparison.Ordinal);
        Assert.Contains("stream=msg-second", emitted[2], StringComparison.Ordinal);
        Assert.Contains("seq=0", emitted[2], StringComparison.Ordinal);
    }

    private static Mock<ILLMResponseProcessor> CreateResponseProcessor(
        List<string> emitted,
        int expectedCount,
        TaskCompletionSource<bool> done)
    {
        var responseProcessor = new Mock<ILLMResponseProcessor>();
        responseProcessor.SetupGet(r => r.RabbitRepo).Returns(Mock.Of<IRabbitRepo>());
        responseProcessor
            .Setup(r => r.ProcessLLMOutput(It.IsAny<LLMServiceObj>()))
            .Callback<LLMServiceObj>(obj =>
            {
                lock (emitted)
                {
                    emitted.Add(obj.LlmMessage ?? string.Empty);
                    if (emitted.Count >= expectedCount)
                    {
                        done.TrySetResult(true);
                    }
                }
            })
            .Returns(Task.CompletedTask);

        return responseProcessor;
    }

    private static async Task WaitFor(Task task, TimeSpan timeout)
    {
        var completed = await Task.WhenAny(task, Task.Delay(timeout));
        if (!ReferenceEquals(completed, task))
        {
            throw new TimeoutException("Timed out waiting for audio output.");
        }

        await task;
    }

    private sealed class FakeAudioGenerator : IAudioGenerator
    {
        private readonly Func<string, CancellationToken, Task<List<string>>> _resolver;

        public FakeAudioGenerator(Func<string, CancellationToken, Task<List<string>>> resolver)
        {
            _resolver = resolver;
        }

        public Task<string> AudioForResponse(string text) => Task.FromResult(string.Empty);

        public Task<List<string>> AudioForResponseChunksOrderedFastFirst(string text) =>
            Task.FromResult(new List<string>());

        public async IAsyncEnumerable<string> StreamAudioInOrder(
            string text,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            var urls = await _resolver(text, ct);
            foreach (var url in urls.Where(u => !string.IsNullOrWhiteSpace(u)))
            {
                ct.ThrowIfCancellationRequested();
                yield return url;
            }
        }

        public List<string> GetChunksFromText(string text, int maxLength = 500) => new();

        public Task<List<string>> AudioForResponseChunks(string text) =>
            Task.FromResult(new List<string>());
    }
}

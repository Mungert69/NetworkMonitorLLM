using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public sealed class AudioStreamProvider
{
    private readonly IAudioGenerator _audioGenerator;
    private readonly ILLMResponseProcessor _responseProcessor;
    private readonly ILogger _logger;
    private readonly string _streamNamespace;
    private static readonly ConcurrentDictionary<string, Task> _audioStreamChains = new(StringComparer.Ordinal);

    public AudioStreamProvider(
        IAudioGenerator audioGenerator,
        ILLMResponseProcessor responseProcessor,
        ILogger logger,
        string streamNamespace)
    {
        _audioGenerator = audioGenerator;
        _responseProcessor = responseProcessor;
        _logger = logger;
        _streamNamespace = string.IsNullOrWhiteSpace(streamNamespace) ? "default" : streamNamespace.Trim();
    }

    public void QueueAudioStreamBestEffort(string responseText, LLMServiceObj baseServiceObj)
    {
        if (string.IsNullOrWhiteSpace(responseText))
        {
            return;
        }

        string sessionKey = GetAudioSessionKey(baseServiceObj);
        if (string.IsNullOrWhiteSpace(sessionKey))
        {
            sessionKey = Guid.NewGuid().ToString("N");
        }

        sessionKey = $"{_streamNamespace}:{sessionKey}";
        Task nextTask;
        while (true)
        {
            var previousTask = _audioStreamChains.GetOrAdd(sessionKey, Task.CompletedTask);
            nextTask = previousTask
                .ContinueWith(
                    _ => StreamAudioBestEffortAsync(responseText, baseServiceObj),
                    CancellationToken.None,
                    TaskContinuationOptions.None,
                    TaskScheduler.Default)
                .Unwrap();

            if (_audioStreamChains.TryUpdate(sessionKey, nextTask, previousTask))
            {
                break;
            }
        }

        _ = nextTask.ContinueWith(
            task =>
            {
                if (task.IsFaulted)
                {
                    _logger.LogWarning(task.Exception, "Queued audio stream failed for session {SessionKey}", sessionKey);
                }

                if (_audioStreamChains.TryGetValue(sessionKey, out var currentTask) &&
                    ReferenceEquals(currentTask, nextTask))
                {
                    _audioStreamChains.TryRemove(sessionKey, out _);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.None,
            TaskScheduler.Default);
    }

    private async Task StreamAudioBestEffortAsync(string responseText, LLMServiceObj baseServiceObj)
    {
        if (string.IsNullOrWhiteSpace(responseText))
        {
            return;
        }

        string audioStreamId = string.IsNullOrWhiteSpace(baseServiceObj.MessageID)
            ? Guid.NewGuid().ToString("N")
            : baseServiceObj.MessageID;
        int audioSequence = 0;
        const int audioChunkStallTimeoutSeconds = 45;
        using var cts = new CancellationTokenSource();
        try
        {
            await using var enumerator = _audioGenerator.StreamAudioInOrder(responseText, cts.Token).GetAsyncEnumerator();
            while (true)
            {
                var nextTask = enumerator.MoveNextAsync().AsTask();
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(audioChunkStallTimeoutSeconds));
                var completed = await Task.WhenAny(nextTask, timeoutTask);
                if (completed != nextTask)
                {
                    cts.Cancel();
                    _logger.LogWarning(
                        "Audio generation stalled for > {Timeout}s and was cancelled for MessageID {MessageID}",
                        audioChunkStallTimeoutSeconds,
                        baseServiceObj.MessageID);
                    try { await nextTask; } catch { }
                    break;
                }

                if (!await nextTask)
                {
                    break;
                }

                var audioUrl = enumerator.Current;
                if (string.IsNullOrWhiteSpace(audioUrl))
                {
                    continue;
                }

                var audioServiceObj = new LLMServiceObj(baseServiceObj);
                audioServiceObj.SetAsNotCall();
                string sequencedAudioUrl = AddAudioSequenceToUrl(audioUrl, audioStreamId, audioSequence);
                audioServiceObj.LlmMessage = $"</audio>{sequencedAudioUrl}";
                _logger.LogInformation(audioServiceObj.LlmMessage);
                await _responseProcessor.ProcessLLMOutput(audioServiceObj);
                audioSequence++;
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Audio generation cancelled for MessageID {MessageID}", baseServiceObj.MessageID);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Audio generation failed for MessageID {MessageID}", baseServiceObj.MessageID);
        }
    }

    private static string GetAudioSessionKey(LLMServiceObj serviceObj)
    {
        if (!string.IsNullOrWhiteSpace(serviceObj.RequestSessionId))
        {
            return serviceObj.RequestSessionId;
        }

        if (!string.IsNullOrWhiteSpace(serviceObj.SessionId))
        {
            return serviceObj.SessionId;
        }

        return "";
    }

    private static string AddAudioSequenceToUrl(string audioUrl, string streamId, int sequence)
    {
        if (string.IsNullOrWhiteSpace(audioUrl))
        {
            return audioUrl;
        }

        string separator = audioUrl.Contains('#') ? "&" : "#";
        return $"{audioUrl}{separator}stream={Uri.EscapeDataString(streamId)}&seq={sequence}";
    }
}

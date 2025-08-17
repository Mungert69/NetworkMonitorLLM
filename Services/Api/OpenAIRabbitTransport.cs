using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using System.Net.Security;
using System.Security.Authentication;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.Repository;   // IRabbitRepo
using NetworkMonitor.Objects.Factory;      // SystemParams / SystemUrl
using NetworkMonitor.Objects;              // ResultObj (if needed)

namespace NetworkMonitor.LLM.Services
{
    /// <summary>
    /// OpenAI-over-RabbitMQ transport.
    /// Uses IRabbitRepo to publish CloudEvent-wrapped requests to the Python server,
    /// and a short-lived consumer bound to a unique reply_key on oa.*.reply to stream back JSON.
    /// </summary>
    public sealed class OpenAIRabbitTransport : IDisposable
    {
        // Server-side exchanges (must match the Python server):
        private const string ChatCreateEx = "oa.chat.create";
        private const string ChatReplyEx = "oa.chat.reply";
        private const string ImgCreateEx = "oa.images.generate";
        private const string ImgReplyEx = "oa.images.reply";

        private readonly ILLMResponseProcessor _responseProcessor;          // your proven publisher
        private readonly SystemUrl _sys;             // for ephemeral consumer connection
        private readonly string _routingKey;         // shard/tenant routing you already use
        private readonly ILogger _log;
        private readonly string _replyExchange = "oa.reply"; // fixed reply exchange

        public OpenAIRabbitTransport(ILLMResponseProcessor responseProcessor, SystemUrl sys, string routingKey, ILogger log)
        {
            _responseProcessor = responseProcessor ?? throw new ArgumentNullException(nameof(responseProcessor));
            _sys = sys ?? throw new ArgumentNullException(nameof(sys));
            _routingKey = routingKey ?? string.Empty;
            _log = log;
        }

        public IAsyncEnumerable<string> CreateChatCompletionStreamAsync(object openAiChatRequest, CancellationToken ct = default)
            => StreamFromServerAsync(ChatCreateEx, ChatReplyEx, openAiChatRequest, ct);

        public async Task<string> CreateImageAsync(object openAiImageRequest, CancellationToken ct = default)
        {
            await foreach (var msg in StreamFromServerAsync(ImgCreateEx, ImgReplyEx, openAiImageRequest, ct))
            {
                // images endpoint returns a single final OpenAI JSON object
                return msg;
            }
            throw new InvalidOperationException("No response from images server.");
        }

        // ---------------- core streaming RPC ----------------

        private async IAsyncEnumerable<string> StreamFromServerAsync(
     string requestExchange,
     string replyExchange,
     object openAiRequest,
     [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            // 1) make a unique reply key (route on reply exchange)
            var replyKey = $"rk.{Guid.NewGuid():N}";

            // 2) create a short-lived connection + channel for the consumer
            var factory = BuildConnectionFactory(_sys);
            await using var conn = await factory.CreateConnectionAsync(ct);
            await using var ch = await conn.CreateChannelAsync();

            // declare reply exchange (idempotent); use DIRECT for precise routing
            await ch.ExchangeDeclareAsync(replyExchange, ExchangeType.Direct, durable: true);
            // exclusive, auto-delete queue for this one call
            var qok = await ch.QueueDeclareAsync(
                queue: $"oa.reply.{Guid.NewGuid():N}",
                durable: false,
                exclusive: true,
                autoDelete: true,
                arguments: null
            );
            await ch.QueueBindAsync(qok.QueueName, replyExchange, replyKey);

            // 3) publish the request via your RabbitRepo (it CloudEvent-wraps for you)
            var requestWithReply = MergeWithReplyKey(openAiRequest, replyKey);
            await _responseProcessor.PublishAsync(requestExchange, requestWithReply, routingKey: _routingKey);

            // 4) start consuming and stream out CloudEvent.data as raw JSON
            var outChan = Channel.CreateUnbounded<string>();
            var consumer = new AsyncEventingBasicConsumer(ch);

            consumer.ReceivedAsync += async (_, ea) =>
            {
                try
                {
                    ct.ThrowIfCancellationRequested();

                    var json = Encoding.UTF8.GetString(ea.Body.ToArray());
                    using var doc = JsonDocument.Parse(json);

                    if (!doc.RootElement.TryGetProperty("data", out var dataEl))
                    {
                        await ch.BasicAckAsync(ea.DeliveryTag, false);
                        return;
                    }

                    if (dataEl.ValueKind == JsonValueKind.Object &&
                        dataEl.TryGetProperty("object", out var objEl) &&
                        objEl.GetString() == "stream.end")
                    {
                        await outChan.Writer.WriteAsync("__STREAM_END__", ct);
                        await ch.BasicAckAsync(ea.DeliveryTag, false);
                        return;
                    }

                    var payload = dataEl.GetRawText();
                    await outChan.Writer.WriteAsync(payload, ct);
                    await ch.BasicAckAsync(ea.DeliveryTag, false);
                }
                catch (OperationCanceledException)
                {
                    await ch.BasicNackAsync(ea.DeliveryTag, false, requeue: true);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "OpenAIRabbitTransport consumer error");
                    await ch.BasicNackAsync(ea.DeliveryTag, false, requeue: false);
                }
            };

            await ch.BasicConsumeAsync(queue: qok.QueueName, autoAck: false, consumer: consumer);

            // 5) yield messages until sentinel or cancellation
            while (await outChan.Reader.WaitToReadAsync(ct))
            {
                while (outChan.Reader.TryRead(out var msg))
                {
                    if (msg == "__STREAM_END__")
                        yield break;

                    yield return msg;
                }
            }
        }

        // ---------------- helpers ----------------

        private static object MergeWithReplyKey(object request, string replyKey)
        {
            // Re-hydrate to dict so we can add reply_key in a provider-agnostic way
            using var doc = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(request));
            var dict = JsonSerializer.Deserialize<Dictionary<string, object?>>(doc.RootElement.GetRawText())
                       ?? new Dictionary<string, object?>();
            dict["reply_key"] = replyKey;
            return dict;
        }

        private static ConnectionFactory BuildConnectionFactory(SystemUrl sys)
        {
            var f = new ConnectionFactory
            {
                HostName = sys.RabbitHostName,
                Port = sys.RabbitPort,
                UserName = sys.RabbitUserName,
                Password = sys.RabbitPassword,
                VirtualHost = sys.RabbitVHost,
                AutomaticRecoveryEnabled = true,
                TopologyRecoveryEnabled = true,
                RequestedHeartbeat = TimeSpan.FromSeconds(30)
                // DispatchConsumersAsync is gone; AsyncEventingBasicConsumer works without it
            };

            if (sys.UseTls)
            {
                f.Ssl = new SslOption
                {
                    Enabled = true,
                    ServerName = sys.RabbitHostName,
                    Version = SslProtocols.Tls12 | SslProtocols.Tls13,
                    AcceptablePolicyErrors =
                        SslPolicyErrors.RemoteCertificateNameMismatch |
                        SslPolicyErrors.RemoteCertificateChainErrors
                };
            }

            return f;
        }

        public void Dispose()
        {
            // nothing to keep; each call scopes its own connection/channel
        }
    }
}

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class NovitaAndLoggingHandlerTests
{
    [Fact]
    public async Task NovitaPathFixHandler_RewritesLegacyPath()
    {
        var capture = new CaptureHandler();
        var handler = new NovitaPathFixHandler { InnerHandler = capture };
        using var invoker = new HttpMessageInvoker(handler);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.novita.ai/v1/chat/completions");
        await invoker.SendAsync(request, CancellationToken.None);

        Assert.Equal("/v3/openai/chat/completions", capture.LastRequest!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task OpenAILoggingHandler_LogsRequestAndResponse()
    {
        var logger = new TestLogger();
        var handler = new OpenAILoggingHandler(logger)
        {
            InnerHandler = new StaticResponseHandler()
        };
        using var invoker = new HttpMessageInvoker(handler);

        var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com")
        {
            Content = new StringContent("payload", Encoding.UTF8, "application/json")
        };

        await invoker.SendAsync(request, CancellationToken.None);

        Assert.Contains(logger.Messages, m => m.Contains("HTTP ->"));
        Assert.Contains(logger.Messages, m => m.Contains("HTTP <-"));
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class StaticResponseHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("response", Encoding.UTF8, "application/json")
            });
        }
    }

    private sealed class TestLogger : ILogger<OpenAILoggingHandler>
    {
        public List<string> Messages { get; } = new();

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}

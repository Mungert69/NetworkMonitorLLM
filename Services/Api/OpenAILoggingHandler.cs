using System.Net.Http;
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
namespace NetworkMonitor.LLM.Services;
internal sealed class OpenAILoggingHandler : DelegatingHandler
{
    private readonly ILogger _logger;
    private readonly bool _logBodies;

    public OpenAILoggingHandler(ILogger<OpenAILoggingHandler> logger, bool logBodies = true)
    {
        _logger = logger;
        _logBodies = logBodies;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        _logger.LogInformation("OpenAI HTTP -> {Method} {Uri}", request.Method, request.RequestUri);
        string? reqBody = null;
        if (_logBodies && request.Content != null)
            reqBody = await request.Content.ReadAsStringAsync(ct);

        _logger.LogDebug(
            "HTTP -> {Method} {Uri}\nHeaders:\n{Headers}\nBody:\n{Body}",
            request.Method, request.RequestUri, request.Headers, _logBodies ? reqBody : "<omitted>");

        var resp = await base.SendAsync(request, ct);

        string? respBody = null;
        if (_logBodies && resp.Content != null)
            respBody = await resp.Content.ReadAsStringAsync(ct);

        _logger.LogDebug(
            "HTTP <- {StatusCode} for {Uri}\nBody:\n{Body}",
            (int)resp.StatusCode, request.RequestUri, _logBodies ? respBody : "<omitted>");

        return resp;
    }
}

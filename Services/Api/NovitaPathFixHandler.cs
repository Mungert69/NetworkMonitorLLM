// File: Services/Api/NovitaPathFixHandler.cs
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
namespace NetworkMonitor.LLM.Services;
internal sealed class NovitaPathFixHandler : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var uri = request.RequestUri!;
        // If SDK built https://api.novita.ai/v1/..., rewrite to .../openai/v1/...
        if (uri.Host.Equals("api.novita.ai", StringComparison.OrdinalIgnoreCase) &&
            (uri.AbsolutePath.Equals("/v1") || uri.AbsolutePath.StartsWith("/v1/")))
        {
            var fixedUri = new Uri($"{uri.Scheme}://{uri.Host}/openai{uri.PathAndQuery}");
            request.RequestUri = fixedUri;
        }
        return base.SendAsync(request, ct);
    }
}

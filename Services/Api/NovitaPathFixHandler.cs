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

        // If SDK built https://api.novita.ai/v1/..., rewrite to .../openai/v3/...
        if (uri.Host.Equals("api.novita.ai", StringComparison.OrdinalIgnoreCase) &&
            (uri.AbsolutePath.Equals("/v1") || uri.AbsolutePath.StartsWith("/v1/")))
        {
            // Rewrite from /v1/... → /openai/v3/...
            var upgradedPath = uri.AbsolutePath.Replace("/v1", "/v3/openai");

            var fixedUri = new UriBuilder(uri)
            {
                Path = upgradedPath
            }.Uri;

            request.RequestUri = fixedUri;
        }

        return base.SendAsync(request, ct);
    }

}

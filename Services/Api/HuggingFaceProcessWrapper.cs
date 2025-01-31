using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Newtonsoft.Json;
using NetworkMonitor.Objects;

namespace NetworkMonitor.LLM.Services
{
    public class HuggingFaceProcessWrapper : ProcessWrapper
    {
        private readonly HttpClient _httpClient;
        private Stream _responseStream;
        private HttpResponseMessage _response;

        public HuggingFaceProcessWrapper(HttpClient httpClient) : base()
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        public async Task InitializeRequest(string url, object payload)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(
                    JsonConvert.SerializeObject(payload),
                    Encoding.UTF8,
                    "application/json")
            };

            _response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            _responseStream = await _response.Content.ReadAsStreamAsync();

            // Mark the process as started
            StartNoProcess(); // This sets HasStarted to true through the base class
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            try
            {
                return await _responseStream.ReadAsync(buffer, offset, count, cancellationToken);
            }
            catch (ObjectDisposedException)
            {
                return 0; // Stream has been closed
            }
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count)
        {
            return await ReadAsync(buffer, offset, count, CancellationToken.None);
        }

        public override void Dispose()
        {
            DisposeManagedResources();
            base.Dispose();
        }

        private void DisposeManagedResources()
        {
            _responseStream?.Dispose();
            _response?.Dispose();
        }
        public override IStreamReader StandardOutput => throw new NotSupportedException("HTTP streams don't support direct stream reader access");
        public override IStreamWriter StandardInput => throw new NotSupportedException("HTTP streams don't support direct stream writer access");
        public override ProcessStartInfo StartInfo => throw new NotSupportedException("HTTP streams don't use ProcessStartInfo");
        public override void Kill() => Dispose(); // Treat kill as dispose for HTTP streams
        public override int Id => -1; // No process ID for HTTP streams
        public override bool HasExited => _responseStream == null || !_responseStream.CanRead;
        public override bool StandardOutputEndOfStream => HasExited;
    }
}
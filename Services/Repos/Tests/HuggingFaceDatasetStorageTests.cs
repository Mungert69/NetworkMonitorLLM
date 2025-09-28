using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using NetworkMonitor.Objects;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceDatasetStorageTests
{
    [Fact]
    public async Task LoadAllSessionsAsync_ParsesJsonFiles()
    {
        var handler = new StubHandler();
        handler.EnqueueResponse(HttpMethod.Get, "https://huggingface.co/api/datasets/repo/tree/main",
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("[{\"path\":\"1_sess.json\"},{\"path\":\"notes.txt\"}]")
            });
        handler.EnqueueResponse(HttpMethod.Get, "https://huggingface.co/api/datasets/repo/resolve/main/1_sess.json",
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(new HistoryDisplayName
                {
                    SessionId = "sess",
                    Name = "Title"
                }))
            });

        var storage = CreateStorage(handler);
        var sessions = await storage.LoadAllSessionsAsync();

        Assert.True(sessions.ContainsKey("sess"));
        Assert.Equal("Title", sessions["sess"].HistoryDisplayName.Name);
    }

    [Fact]
    public async Task SaveHistoryAsync_UploadsSerializedContent()
    {
        var handler = new StubHandler();
        handler.EnqueueResponse(HttpMethod.Put, "https://huggingface.co/api/datasets/repo/write/main/5_id.json",
            new HttpResponseMessage(HttpStatusCode.OK));

        var storage = CreateStorage(handler);
        await storage.SaveHistoryAsync(new HistoryDisplayName
        {
            SessionId = "id",
            StartUnixTime = 5,
            Name = "Saved"
        });

        var recorded = handler.Requests.Single(r => r.Method == HttpMethod.Put);
        var body = await recorded.Content!.ReadAsStringAsync();
        Assert.Contains("\"saved\"", body.ToLowerInvariant());
    }

    [Fact]
    public async Task DeleteHistoryAsync_IssuesDeleteRequests()
    {
        var handler = new StubHandler();
        handler.EnqueueResponse(HttpMethod.Get, "https://huggingface.co/api/datasets/repo/tree/main",
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("[{\"path\":\"10_target.json\"}]")
            });
        handler.EnqueueResponse(HttpMethod.Delete, "https://huggingface.co/api/datasets/repo/delete/main/10_target.json",
            new HttpResponseMessage(HttpStatusCode.NoContent));

        var storage = CreateStorage(handler);
        await storage.DeleteHistoryAsync("target");

        Assert.Contains(handler.Requests, r => r.Method == HttpMethod.Delete && r.RequestUri!.AbsoluteUri.Contains("target.json"));
    }

    private static HuggingFaceDatasetStorage CreateStorage(StubHandler handler)
    {
        var mlParams = new MLParams
        {
            DataRepoId = "repo",
            HFToken = "token"
        };
        var storage = new HuggingFaceDatasetStorage(mlParams);

        var client = new HttpClient(handler)
        {
            BaseAddress = new System.Uri("https://huggingface.co/")
        };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "token");

        var field = typeof(HuggingFaceDatasetStorage).GetField("_httpClient", BindingFlags.NonPublic | BindingFlags.Instance)!;
        field.SetValue(storage, client);

        return storage;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Queue<(HttpMethod method, string uri, HttpResponseMessage response)> _responses = new();
        public List<HttpRequestMessage> Requests { get; } = new();

        public void EnqueueResponse(HttpMethod method, string uri, HttpResponseMessage response)
        {
            _responses.Enqueue((method, uri, response));
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(CloneRequest(request));

            if (_responses.Count == 0)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            var next = _responses.Peek();
            if (next.method != request.Method || next.uri != request.RequestUri!.AbsoluteUri)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            _responses.Dequeue();
            return Task.FromResult(next.response);
        }

        private static HttpRequestMessage CloneRequest(HttpRequestMessage request)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri);
            if (request.Content != null)
            {
                var contentTask = request.Content.ReadAsStringAsync();
                contentTask.Wait();
                clone.Content = new StringContent(contentTask.Result);
            }
            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            return clone;
        }
    }
}

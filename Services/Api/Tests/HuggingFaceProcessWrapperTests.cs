using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceProcessWrapperTests
{
    [Fact]
    public async Task InitializeRequest_ReadsStreamThroughWrapper()
    {
        var handler = new StubHandler("hello");
        using var client = new HttpClient(handler);
        var wrapper = new HuggingFaceProcessWrapper(client);

        await wrapper.InitializeRequest("https://example.com", "{}");

        var buffer = new byte[5];
        var read = await wrapper.ReadAsync(buffer, 0, buffer.Length);
        Assert.Equal(5, read);
        Assert.Equal("hello", Encoding.UTF8.GetString(buffer));

        var second = await wrapper.ReadAsync(buffer, 0, buffer.Length);
        Assert.Equal(0, second);

        wrapper.Dispose();
        Assert.True(wrapper.HasExited);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _payload;

        public StubHandler(string payload)
        {
            _payload = payload;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_payload, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }
}

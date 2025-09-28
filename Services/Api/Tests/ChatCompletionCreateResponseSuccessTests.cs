using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class ChatCompletionCreateResponseSuccessTests
{
    [Fact]
    public void Properties_AreSettable()
    {
        var response = new ChatCompletionCreateResponse { Id = "resp-123" };

        var wrapper = new ChatCompletionCreateResponseSuccess
        {
            Success = true,
            Response = response
        };

        Assert.True(wrapper.Success);
        Assert.Same(response, wrapper.Response);
    }
}

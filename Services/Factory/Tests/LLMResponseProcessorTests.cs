using System.Collections.Generic;
using System.Threading.Tasks;
using Moq;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Objects.ServiceMessage;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class LLMResponseProcessorTests
{
    private readonly Mock<IRabbitRepo> _rabbitRepo = new();
    private readonly LLMResponseProcessor _processor;

    public LLMResponseProcessorTests()
    {
        _processorsetup();
        _processor = new LLMResponseProcessor(_rabbitRepo.Object);
    }

    private void _processorsetup()
    {
        _rabbitRepo
            .Setup(r => r.PublishAsync<LLMServiceObj>(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        _rabbitRepo
            .Setup(r => r.PublishAsync(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
    }

    [Fact]
    public async Task ProcessLLMOutput_PublishesSuccessMessage()
    {
        var obj = new LLMServiceObj { LlmMessage = "content" };

        await _processor.ProcessLLMOutput(obj);

        _rabbitRepo.Verify(r => r.PublishAsync<LLMServiceObj>("llmServiceMessage", obj, It.IsAny<string>()), Times.Once);
        Assert.True(obj.ResultSuccess);
    }

    [Fact]
    public async Task ProcessFunctionCall_TracksAndPublishes()
    {
        var obj = new LLMServiceObj { MessageID = "mid", LlmMessage = "payload" };

        await _processor.ProcessFunctionCall(obj);

        _rabbitRepo.Verify(r => r.PublishAsync<LLMServiceObj>("llmServiceFunction", obj, It.IsAny<string>()), Times.Once);
        Assert.False(_processor.AreAllFunctionsProcessed("mid"));

        var mark = new LLMServiceObj { MessageID = "mid", FunctionCallId = obj.FunctionCallId, UserInput = "user", FunctionName = "func" };
        _processor.MarkFunctionAsProcessed(mark);

        Assert.True(_processor.AreAllFunctionsProcessed("mid"));
        var processed = _processor.GetProcessedFunctionCalls("mid");
        Assert.Single(processed);
        Assert.Equal("user", processed[0].UserInput);
    }

    [Fact]
    public async Task PublishAsync_UsesRabbitRepo()
    {
        await _processor.PublishAsync("exchange", new { Value = 1 }, "route");

        _rabbitRepo.Verify(r => r.PublishAsync("exchange", It.IsAny<object>(), "route"), Times.Once);
    }
}

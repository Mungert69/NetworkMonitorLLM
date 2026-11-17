using System.Collections.Generic;
using System.Reflection;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using Microsoft.Extensions.Logging;
using Moq;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class HuggingFaceProviderTests
{
    private readonly Mock<IToolsBuilder> _toolsBuilder = new();
    private readonly Mock<ILLMResponseProcessor> _responseProcessor = new();
    private readonly Mock<ILogger> _logger = new();
    private readonly MLParams _mlParams;

    public HuggingFaceProviderTests()
    {
        _mlParams = new MLParams
        {
            LlmHFModelVersion = "llama_3.2",
            LlmTemp = "0.25",
            LlmHFModelID = "model",
            LlmHFKey = "key",
            LlmHFUrl = "https://api.novita.ai/v3/openai/chat/completions",
            XmlFunctionParsing = true,
            NoNShot = true,
            LlmHfSupportsFunctionCalling = true
        };

        _toolsBuilder.SetupGet(t => t.Tools).Returns(new List<ToolDefinition>());
        _toolsBuilder
            .Setup(t => t.GetSystemPrompt(It.IsAny<string>(), It.IsAny<LLMServiceObj>(), "HugLLM"))
            .Returns(() => new List<ChatMessage> { ChatMessage.FromSystem("base") });
    }

    private HuggingFaceApi CreateApi()
        => new(_logger.Object, _mlParams, _toolsBuilder.Object, "service", _responseProcessor.Object);

    private static string BuildStructuredPayloadJson(HuggingFaceApi api)
    {
        var messages = new List<ChatMessage> { ChatMessage.FromUser("hello") };

        var convert = typeof(HuggingFaceApi).GetMethod("ConvertMessagesForOpenAIToolMode", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var structuredMessages = (List<Dictionary<string, object?>>)convert.Invoke(api, new object[] { messages })!;

        var buildPayload = typeof(HuggingFaceApi).GetMethod("BuildPayload", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var payload = buildPayload.Invoke(api, new object?[] { messages, 128, null, structuredMessages })!;

        return Serialize(payload);
    }

    private static string BuildTextPayloadJson(HuggingFaceApi api)
    {
        var messages = new List<ChatMessage> { ChatMessage.FromUser("hello") };

        var buildPayload = typeof(HuggingFaceApi).GetMethod("BuildPayload", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var payload = buildPayload.Invoke(api, new object?[] { messages, 128, null, null })!;

        return Serialize(payload);
    }

    private static string Serialize(object payload)
    {
        return JsonConvert.SerializeObject(payload, Formatting.None, new JsonSerializerSettings
        {
            ContractResolver = new CamelCasePropertyNamesContractResolver(),
            NullValueHandling = NullValueHandling.Ignore
        });
    }

    [Theory]
    [InlineData("https://openrouter.ai/api/v1/chat/completions", HuggingFaceProvider.OpenRouter)]
    [InlineData("https://api.novita.ai/v3/openai/chat/completions", HuggingFaceProvider.Novita)]
    [InlineData("https://router.huggingface.co/v1/chat/completions", HuggingFaceProvider.HuggingFace)]
    [InlineData("https://example.com/v1/chat/completions", HuggingFaceProvider.Unknown)]
    public void Resolve_DetectsProviderFromUrl(string url, HuggingFaceProvider expected)
    {
        Assert.Equal(expected, HuggingFaceProviderResolver.Resolve(null, url));
        Assert.Equal(expected, HuggingFaceProviderResolver.Resolve("Auto", url));
    }

    [Fact]
    public void Resolve_ConfiguredProviderWinsOverUrl()
    {
        Assert.Equal(
            HuggingFaceProvider.OpenRouter,
            HuggingFaceProviderResolver.Resolve("OpenRouter", "https://api.novita.ai/v3/openai/chat/completions"));
    }

    [Fact]
    public void SupportsProviderRouting_OnlyForOpenRouter()
    {
        Assert.True(HuggingFaceProviderResolver.SupportsProviderRouting(HuggingFaceProvider.OpenRouter));
        Assert.False(HuggingFaceProviderResolver.SupportsProviderRouting(HuggingFaceProvider.Novita));
        Assert.False(HuggingFaceProviderResolver.SupportsProviderRouting(HuggingFaceProvider.HuggingFace));
        Assert.False(HuggingFaceProviderResolver.SupportsProviderRouting(HuggingFaceProvider.Unknown));
    }

    [Fact]
    public void BuildPayload_OmitsProviderBlock_ForNovita()
    {
        _mlParams.LlmHFUrl = "https://api.novita.ai/v3/openai/chat/completions";

        var json = BuildStructuredPayloadJson(CreateApi());

        Assert.DoesNotContain("\"provider\"", json);
    }

    [Fact]
    public void BuildPayload_IncludesProviderBlock_ForOpenRouter()
    {
        _mlParams.LlmHFUrl = "https://openrouter.ai/api/v1/chat/completions";

        var json = BuildStructuredPayloadJson(CreateApi());

        Assert.Contains("\"provider\":{\"sort\":\"price\"}", json);
    }

    [Fact]
    public void BuildPayload_OmitsProviderBlock_WhenProviderIsUnknown()
    {
        _mlParams.LlmHFUrl = "https://example.com/v1/chat/completions";

        var json = BuildStructuredPayloadJson(CreateApi());

        Assert.DoesNotContain("\"provider\"", json);
    }

    [Fact]
    public void BuildPayload_IncludesProviderBlock_WhenProviderConfiguredExplicitly()
    {
        _mlParams.LlmHFUrl = "https://example.com/v1/chat/completions";
        _mlParams.LlmHfProvider = "OpenRouter";

        var json = BuildStructuredPayloadJson(CreateApi());

        Assert.Contains("\"provider\":{\"sort\":\"price\"}", json);
    }

    [Fact]
    public void BuildTextPayload_OmitsProviderBlock_ForNovita()
    {
        _mlParams.LlmHFUrl = "https://api.novita.ai/v3/openai/chat/completions";
        _mlParams.LlmHfSupportsFunctionCalling = false;

        var json = BuildTextPayloadJson(CreateApi());

        Assert.DoesNotContain("\"provider\"", json);
        Assert.Contains("\"max_tokens\":128", json);
        Assert.Contains("\"response_format\":{\"type\":\"text\"}", json);
    }

    [Fact]
    public void BuildTextPayload_IncludesProviderBlock_ForOpenRouter()
    {
        _mlParams.LlmHFUrl = "https://openrouter.ai/api/v1/chat/completions";
        _mlParams.LlmHfSupportsFunctionCalling = false;

        var json = BuildTextPayloadJson(CreateApi());

        Assert.Contains("\"provider\":{\"sort\":\"price\"}", json);
    }
}

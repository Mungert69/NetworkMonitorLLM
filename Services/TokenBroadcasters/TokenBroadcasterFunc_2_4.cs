using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.LLM.Services.Objects;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Linq;
using NetworkMonitor.Objects;
namespace NetworkMonitor.LLM.Services;
public class TokenBroadcasterFunc_2_4 : TokenBroadcasterBase
{

    public TokenBroadcasterFunc_2_4(ILLMResponseProcessor responseProcessor, ILogger logger,bool xmlFunctionParsing = false)
         : base(responseProcessor, logger,xmlFunctionParsing)
    {
      
    }

  

    public override async Task BroadcastAsync(ProcessWrapper process, LLMServiceObj serviceObj, string userInput)
    {
        _logger.LogWarning($" Start BroadcastAsync() DestinationLlm {serviceObj.DestinationLlm} SourceLlm {serviceObj.SourceLlm} ");

        var llmOutFull = new StringBuilder();
        var tokenBuilder = new StringBuilder();
        var forwardSegments = new List<MessageSegment>();

        bool isStopEncountered = false;
        try
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                byte[] buffer = new byte[50];
                int charRead = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
                string textChunk = Encoding.UTF8.GetString(buffer, 0, charRead);
                await SendLLMPrimaryChunk(serviceObj,textChunk);
                llmOutFull.Append(textChunk);
                tokenBuilder.Append(textChunk);
                //Console.WriteLine(textChunk);
                if (IsTokenComplete(tokenBuilder))
                {
                    string token = tokenBuilder.ToString();
                    tokenBuilder.Clear();
                    token = token.Replace("/\b", "");
                    //Console.WriteLine(token);
                }
                //var (messageSegment, isWithinContent, isMessageSegmentComplete) = ParseLLMOutput(llmOutFull.ToString());
                var (messageSegments, isMessageSegmentsComplete) = ParseLLMOutputMulti(llmOutFull.ToString());
                if (isMessageSegmentsComplete && messageSegments != null && messageSegments.Count > 0)
                {
                    foreach (var messageSegment in messageSegments)
                    {
                        if (serviceObj.IsFunctionCallResponse) await SendLLMPrimaryChunk( serviceObj,"</functioncall-complete>");
                        await ProcessMessageSegment(messageSegment, serviceObj);
                    }
                    if (!_isPrimaryLlm) forwardSegments = messageSegments;
                    _cancellationTokenSource.Cancel();
                    isStopEncountered = true;
                }
                if (isStopEncountered)
                    break;
            }
            if (!_isPrimaryLlm && !_isFuncCalled)
            {
                string llmOutput = "Message to sent from Remote LLM format corrupt.";
                //string test = llmOutFull.ToString();
                try
                {
                    if (forwardSegments.Count > 0)
                    {
                        var assistantSegment = forwardSegments.Where(a => a.From.Contains("assistant")).FirstOrDefault();
                        if (assistantSegment != null) {
                            llmOutput = assistantSegment.Content.Replace("<|stop|>", "");
                            if (!isSystemLlm) llmOutput = assistantSegment.Content.Replace("\n", "") ;   
                        }
                    }
                }
                catch { }

                var finalServiceObj = new LLMServiceObj(serviceObj);
                finalServiceObj.LlmMessage = llmOutput;
                finalServiceObj.IsFunctionCall = false;
                finalServiceObj.IsFunctionCallResponse = true;
                await SendLLM(finalServiceObj);
                _logger.LogInformation($" --> Sent redirected LLM Output {finalServiceObj.LlmMessage}");
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Read operation canceled due to CancellationToken.");
            await SendLLMPrimaryChunk(serviceObj,"\n");
           
        }
        finally
        {
          await SendLLMPrimaryChunk(serviceObj, "</llm-listening>");    
        }

        _logger.LogInformation(" --> Finished LLM Interaction ");
    }


    public static (MessageSegment, bool, bool) ParseLLMOutput(string output)
    {
        var regex = new Regex(@"<\|(?<tag>\w+)\|>(?<value>.+?(?=<\|))");
        string outputClean = output.Replace("\n", ""); // Remove newlines
        string from = "";
        string recipient = "";
        string content = "";
        bool isWithinContent = false;
        bool isMessageSegmentComplete = false;
        if (output.Contains("<|stop|>"))
        {
            isMessageSegmentComplete = true;
        }
        var matches = regex.Matches(outputClean);
        foreach (Match match in matches)
        {
            var tag = match.Groups["tag"].Value;
            string value = match.Groups["value"].Value;
            switch (tag)
            {
                case "from":
                    from = value.Trim();
                    break;
                case "recipient":
                    recipient = value.Trim();
                    break;
                case "content":
                    isWithinContent = true;
                    content = value.Trim();
                    break;
            }
        }
        var messageSegment = new MessageSegment()
        {
            From = from,
            Recipient = recipient,
            Content = content
        };
        return (messageSegment, isWithinContent, isMessageSegmentComplete);
    }

    public static (List<MessageSegment>, bool) ParseLLMOutputMulti(string output)
    {
        bool isMessageSegmentsComplete = false;
        var regex = new Regex(@"<\|(?<tag>\w+)\|>(?<value>.+?(?=<\|)|.+?(?=\\n\|<\\|))");
        string outputClean = output.Replace("\n", ""); // Remove newlines
        var messageSegments = new List<MessageSegment>();
        var matches = regex.Matches(outputClean);
        if (output.Contains("<|stop|>"))
        {
            isMessageSegmentsComplete = true;
            MessageSegment? currentSegment = null;

            foreach (Match match in matches)
            {
                var tag = match.Groups["tag"].Value;
                string value = match.Groups["value"].Value;
                switch (tag)
                {
                    case "from":
                    
                        if (currentSegment == null);
                        {
                            currentSegment = new MessageSegment();
                        }
                        currentSegment.From = value.Trim();
                        break;
                    case "recipient":
                        if (currentSegment == null)
                        {
                            currentSegment = new MessageSegment();
                        }
                        currentSegment.Recipient = value.Trim();
                        break;
                    case "content":
                        if (currentSegment == null)
                        {
                            currentSegment = new MessageSegment();
                        }
                        currentSegment.Content = value.Trim();
                        messageSegments.Add(currentSegment);
                        currentSegment = null; // Reset for the next segment
                        break;
                }
            }
        }

        return (messageSegments, isMessageSegmentsComplete);
    }

    private static string ReadUntil(string input, int startIndex, char stopChar)
    {
        var sb = new System.Text.StringBuilder();
        while (startIndex < input.Length && input[startIndex] != stopChar)
        {
            sb.Append(input[startIndex]);
            startIndex++;
        }
        return sb.ToString();
    }
    private async Task ProcessMessageSegment(MessageSegment messageSegment, LLMServiceObj serviceObj)
    {
        //LLMServiceObj responseServiceObj = new LLMServiceObj() { SessionId = sessionId, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
        var responseServiceObj = new LLMServiceObj(serviceObj);
        string line = messageSegment.Content;

        if (messageSegment.From == "assistant" && messageSegment.Recipient != "all")
        {
            var (isJson, jsonLine) = ParseSegmentInputForJson(line);
            //string cleanLine = line;
            if (isJson)
            {
                var jsonFunction = "{\"name\" : \"" + messageSegment.Recipient + "\" , \"parameters\" : " + jsonLine + "}";
                _logger.LogInformation($" ProcessLLMOutput(call_func) -> {jsonLine}");
                //responseServiceObj = new LLMServiceObj() { SessionId = sessionId, UserInput = userInput, SourceLlm = sourceLlm, DestinationLlm = destinationLlm };
                responseServiceObj.LlmMessage = "</functioncall>";
                if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
                else
                {
                    var forwardFuncServiceObj = new LLMServiceObj(responseServiceObj);
                    forwardFuncServiceObj.LlmMessage = $"Please wait calling function. Be patient this may take some time";
                    forwardFuncServiceObj.IsFunctionCall = false;
                    forwardFuncServiceObj.IsFunctionCallResponse = true;
                    forwardFuncServiceObj.FunctionName = messageSegment.Recipient;
                    // await _responseProcessor.ProcessLLMOutput(forwardFuncServiceObj);
                    // _logger.LogInformation($" --> Sent redirected LLM Function Output {forwardFuncServiceObj.LlmMessage}");

                }
                responseServiceObj.LlmMessage = "";
                responseServiceObj.IsFunctionCall = true;
                responseServiceObj.JsonFunction = jsonFunction;
                responseServiceObj.FunctionName = messageSegment.Recipient;
                //responseServiceObj.JsonFunction = CallFuncJson(cleanLine);
                await _responseProcessor.ProcessFunctionCall(responseServiceObj);
                _isFuncCalled = true;
            }
        }
        responseServiceObj.LlmMessage = "<end-of-line>";
        if (_isPrimaryLlm) await _responseProcessor.ProcessLLMOutput(responseServiceObj);
    }
    public string CallFuncJson(string input)
    {
        string callFuncJson = "";
        string funcName = "addHost";
        int startIndex = input.IndexOf('{');
        int lastClosingBraceIndex = input.LastIndexOf('}');
        string json = "";
        if (startIndex != -1)
        {
            json = input.Substring(startIndex, lastClosingBraceIndex + 1);
        }
        callFuncJson = "{ \"name\" : \"" + funcName + "\" \"arguments\" : \"" + json + "\"}";
        return callFuncJson;
    }
    private (bool, string) ParseSegmentInputForJson(string input)
    {
        string newLine = string.Empty;
        // bool foundStart = false;
        bool foundEnd = false;
        int startIndex = input.IndexOf('{');
        // If '{' is not found or is too far into the input, return the original input
        if (startIndex == -1)
        {
            return (false, input);
        }
        newLine = input.Substring(startIndex);
        int lastClosingBraceIndex = newLine.LastIndexOf('}');
        if (lastClosingBraceIndex != -1)
        {
            newLine = newLine.Substring(0, lastClosingBraceIndex + 1);
            foundEnd = true;
        }
        if (foundEnd) return (true, JsonSanitizer.SanitizeJson(newLine));
        else return (false, input);
    }
}
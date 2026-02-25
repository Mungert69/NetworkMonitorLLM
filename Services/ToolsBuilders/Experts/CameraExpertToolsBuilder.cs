using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System.Collections.Generic;
using NetworkMonitor.Objects.ServiceMessage;

namespace NetworkMonitor.LLM.Services;

public class CameraExpertToolsBuilder : ToolsBuilderBase
{
    private readonly FunctionDefinition fn_run_camera_capture;

    public CameraExpertToolsBuilder()
    {
        fn_run_camera_capture = CameraTools.BuildCaptureFunction();
        _tools = new List<ToolDefinition>
        {
            new ToolDefinition { Function = fn_run_camera_capture, Type = "function" }
        };
    }

    public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
    {
        string content = @"
You are the Camera Expert for Network Monitor.
- Capture a still image first using run_camera_capture.
- Prefer protocol=rtsp unless user explicitly requests onvif.
- Use high_detail=false by default; set high_detail=true only when finer visual detail is required.
- If credentials are missing, ask for the minimum missing fields.
- After capture, summarize clearly what can be inferred from the returned function payload.
- If image content is unavailable or capture failed, explain the failure and next corrective step.
";
        content += $" Current time: {currentTime}.";
        return new List<ChatMessage> { new ChatMessage { Role = "system", Content = content } };
    }
}

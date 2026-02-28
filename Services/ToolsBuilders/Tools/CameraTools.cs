using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public static class CameraTools
{
    public static FunctionDefinition BuildCaptureFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_camera_capture",
            Description = "Capture a single still image from an IP camera using RTSP or ONVIF Profile S and return an image URL plus metadata in the function result. Use this when the user asks to inspect or analyze what a camera currently sees.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["address"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Camera host/IP or URL. For RTSP this can be host, host/path, or full rtsp:// URL. For ONVIF this can be host/IP or media service URL."
                    },
                    ["protocol"] = new PropertyDefinition
                    {
                        Type = "string",
                        Enum = new List<string> { "rtsp", "onvif" },
                        Description = "Camera protocol. Use rtsp for stream frame capture, onvif for Profile S snapshot flow."
                    },
                    ["username"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional camera username."
                    },
                    ["password"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional camera password."
                    },
                    ["profile_token"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional ONVIF profile token. Defaults to Profile_1."
                    },
                    ["rtsp_path"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional RTSP path when address is host-only."
                    },
                    ["rtsp_port"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Optional RTSP port override (for example 554). If omitted, address/default behavior is used."
                    },
                    ["onvif_port"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Optional ONVIF HTTP(S) port override (for example 2020). If omitted, camera-specific and generic ONVIF discovery defaults are used."
                    },
                    ["high_detail"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Set true for higher detail capture (1280 long edge). Defaults to false (1024 long edge)."
                    },
                    ["allow_insecure_tls"] = new PropertyDefinition
                    {
                        Type = "boolean",
                        Description = "Optional TLS setting for ONVIF HTTPS cameras with self-signed certificates. Defaults to true."
                    },
                    ["ffmpeg_path"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional ffmpeg executable path override. Defaults to ffmpeg."
                    },
                    ["instruction"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional analysis instruction (for example: count people, detect open door, check package presence)."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Agent location that will perform camera capture."
                    }
                },
                Required = new List<string> { "address", "agent_location" }
            }
        };
    }
}

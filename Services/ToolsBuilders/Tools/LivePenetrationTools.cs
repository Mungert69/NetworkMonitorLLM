using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System.Collections.Generic;

namespace NetworkMonitor.LLM.Services;

public static class LivePenetrationTools
{
    public static FunctionDefinition BuildInteractMsfconsoleFunction()
    {
        return new FunctionDefinition
        {
            Name = "interact_msfconsole",
            Description = "Interact with the persistent msfconsole owned by this live penetration session. " +
                          "Commands and Metasploit jobs/sessions remain available between calls when the same agent_location is used. " +
                          "Responses include busy and commandComplete. Large output is returned as a bounded beginning and latest end " +
                          "with outputTruncated and omittedCharacters metadata; refine the console command instead of retrieving an entire omitted listing. " +
                          "For an ordinary running Framework command, read until it completes. After output confirms an attached shell or Meterpreter prompt, " +
                          "busy and commandComplete may remain active-state values while one interactive command at a time is accepted.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["input"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Exactly one command to send to the active msfconsole, Meterpreter, or shell prompt. " +
                                      "Do not batch commands with semicolons, embedded newlines, &&, or similar separators. " +
                                      "A terminating newline is added when needed; inspect the response before sending the next command."
                    },
                    ["control"] = new PropertyDefinition
                    {
                        Type = "string",
                        Enum = new List<string> { "write", "read", "detach", "interrupt", "close" },
                        Description = "write (default), read buffered output, detach the active session, interrupt it, or close the console. " +
                                      "Detach backgrounds an attached session and does not terminate the session, handler, job, listener, or target process."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Agent hosting this live console. Use exactly the same location for the entire live session."
                    },
                    ["wait_seconds"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Maximum time to wait for Metasploit to become ready. Default and maximum: 60 seconds."
                    }
                },
                Required = new List<string> { "agent_location" }
            }
        };
    }
}

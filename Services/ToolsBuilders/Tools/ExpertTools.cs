using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Factory;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;

namespace NetworkMonitor.LLM.Services;

public class ExpertTools
{
    public static FunctionDefinition BuildMonitorExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_monitor_expert",
            Description = "Communicate a monitoring management request to the Monitor System Expert LLM. Use this for host monitoring lifecycle operations such as add/edit hosts, list monitored hosts, fetch host monitoring data, and reset monitor alerts.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "A concise but complete request for the monitor expert. Include the target host(s), monitor type/protocol details, interval/timeout settings when relevant, and desired operation."
                    }
                },
                Required = new List<string> { "message" }
            }
        };
    }

    public static FunctionDefinition BuildSecurityExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_security_expert",
            Description = "Communicate a security assessment request to a Security Expert LLM. You will craft a detailed message describing the user's request for a security assessment, which may involve either network scans using Nmap or security checks using OpenSSL. The message should specify the type of assessment (e.g., vulnerability scan, SSL/TLS configuration check), the target (e.g., IP address, domain, or service), and any relevant parameters or instructions. Ensure the message clearly outlines the user's security goals. If the security expert LLM requires additional information, present these queries to the user in simple terms and assist in formulating the appropriate responses based on your understanding",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The message to be sent to the security expert LLM, detailing the assessment request and parameters, including scan type (Nmap or OpenSSL), target, and any special instructions. Always include confirmation that you are authorized to perform this action"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location that will execute the secutiry assessment."
                    }
                },
                Required = new List<string> { "message","agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildPenetrationExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_penetration_expert",
            Description = "Communicate a penetration testing request to a remote penetration expert LLM. DO NOT use for nmap, openssl or security scans use the Security expert for these requests. If the user requires a penetration test you will craft a detailed message describing the user's request for penetration testing to be passed to the penetration expert. If the Metasploit expert requires further details try to provide these without asking the user if possible. The penetration expert can also search the metasploit database using msfconsole search.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The message to be sent to the Metasploit expert LLM, detailing the penetration testing request. Always include confirmation that you are authorized to perform this action"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location that will execute the penetration test."
                    }
                },
                Required = new List<string> { "message","agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildSearchExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_search_expert",
            Description = "Communicate a request to access the internet to a Search Expert LLM. You can ask the search expert to read a given url or web page. It will return the text and links on the page. You can also ask the search expert to perform a web search using a search engine. When requesting a search engine search you will craft a detailed message describing the user's search query, which may involve general information retrieval, fact-checking, or finding specific data. The message should specify the search terms, any filters or constraints, and the type of information needed. If the search expert LLM requires additional information, present these queries to the user in simple terms and assist in formulating the appropriate responses based on your understanding. The search engine search will return a list of urls that can then be browsed indivdually. You can ask the search expert to read the text on these pages. Warning a web search can take sometime and use a lot of tokens",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The message to be sent to the search expert LLM, detailing the type of request: read a page or perform a search. And the search term or web page url. Always include confirmation that you are authorized to perform this action"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location that will perform the web search"
                    }
                },
                Required = new List<string> { "message","agent_location"}
            }
        };
    }

    public static FunctionDefinition BuildCmdProcessorExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_cmd_processor_expert",
            Description = "Communicate a cmd processor management request to a Cmd Processor Expert LLM. This expert can create, list, run, provide help for, show source code, and delete custom .NET running command processors on a specified agent. Users do not need detailed .NET knowledge; they can simply request operations or even ask to view or modify the source code. For example, they might say 'list available cmd processors', 'add a new cmd processor named X', 'run the cmd processor with arguments Y', 'get help for a cmd processor', 'show me the source code of cmd processor X', or 'update cmd processor X with this new source code'. Note: the expert does not have access to the context of this conversation so be sure to give all the information it needs to perform the task. You can use your .net code knowlede to work in colaberation with the cmd processor expert to fulfil the users request",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "A detailed message describing what you want the cmd processor expert to do. This can include requests to list available cmd processors, create or update cmd processors, run a cmd processor with certain arguments, retrieve or display its source code, show help information, or delete a cmd processor. The expert will parse this request and respond accordingly, prompting for further details if needed. IMPORTANT the expert DOES NOT have access to your conversation with the user. If you want it to use informaton from the conversation you must include it in the message. For example if you have source_code that you want it to use then you MUST suppy this in your request for it to create or update a cmd processor. Always include confirmation that you are authorized to perform this action"
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location on which the cmd processors should be managed."
                    }
                },
                Required = new List<string> { "message","agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildAgentFlowExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_agent_flow_expert",
            Description = "Communicate a request to an Agent Flow expert that designs Agenic-Flow graph JSON files. Use this to build or revise agent flow JSON for a given goal. The expert returns only JSON.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "A concise, complete description of the desired agent flow, including goal, required tools, constraints, and any example inputs. The expert does not see the rest of this chat."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional: include a preferred agent location if the flow should default to a specific agent."
                    }
                },
                Required = new List<string> { "message" }
            }
        };
    }

    public static FunctionDefinition BuildConnectExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_connect_expert",
            Description = "Communicate a connect management request to a Connect Expert LLM. This expert creates and manages custom .NET endpoint types (Connects) that run periodically as part of monitoring. The monitoring system handles scheduling; Connects define the endpoint logic and cannot be run manually like cmd processors. Use this when the user wants to add, list, delete, or view Connect source.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "A concise message describing what you want the connect expert to do. Include connect_type and the desired behavior. Use this to request adding a new Connect, listing Connects, deleting a Connect, or retrieving its source code. Always include confirmation that you are authorized to perform this action."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location on which the connect types should be managed."
                    }
                },
                Required = new List<string> { "message","agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildQuantumExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_quantum_expert",
            Description = "Communicate a quantum security assessment request to a Quantum Expert LLM. You will craft a detailed message describing the user's request for quantum safety validation, which may involve testing TLS KEM support, scanning quantum-vulnerable ports, or validating quantum-resistant certificate usage and configurations. The message should specify target servers, any algorithm preferences if provided, and any special parameters; include ports only when the user provides them. For general \"quantum readiness\" requests, encourage coverage of both TLS KEM and certificate checks, and consider a port scan when appropriate. If the quantum expert requires additional information, present these queries to the user in simple terms and assist in formulating appropriate responses.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The message to send to the quantum expert LLM should include:\n" +
                                      "1. Target server(s) or IP addresses to assess\n" +
                                      "2. Specific quantum algorithms to test (if the user provides), or omit to test all supported TLS KEMs.\n" +
                                      "3. Ports to scan for quantum vulnerabilities (if the user provides) or allow the expert to choose.\n" +
                                      "Example: \"Test example.com for TLS KEM support and post-quantum certificate usage, and perform a quantum readiness scan\""
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location that will execute the quantum assessment."
                    }
                },
                Required = new List<string> { "message","agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildCameraExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_camera_expert",
            Description = "Communicate an image capture and inspection request to the Camera Expert LLM. Use this when the user wants a camera snapshot analyzed. Include camera address/protocol details and the specific visual task.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "A complete request for the camera expert, including what to capture and what to analyze in the image. Include camera details and any constraints. Always include confirmation that you are authorized to perform this action."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location that should execute the camera capture."
                    }
                },
                Required = new List<string> { "message", "agent_location" }
            }
        };
    }

    public static FunctionDefinition BuildMemoryExpertFunction()
    {
        return new FunctionDefinition
        {
            Name = "call_memory_expert",
            Description = "Communicate a memory retrieval request to the Memory Expert LLM. Use this when the user asks about prior conversation details that may be out of current context due to trimming.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["message"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "A concise memory retrieval objective including what needs to be recalled and relevant scope hints."
                    },
                    ["user_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. User id for memory filtering."
                    },
                    ["session_id"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Optional. Session id for narrow memory lookup."
                    }
                },
                Required = new List<string> { "message" }
            }
        };
    }
}

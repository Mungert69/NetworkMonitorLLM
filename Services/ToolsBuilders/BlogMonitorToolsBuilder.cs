using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.Factory;
using OpenAI;
using OpenAI.Builders;
using OpenAI.Managers;
using OpenAI.ObjectModels;
using OpenAI.ObjectModels.RequestModels;
using OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using System.Net.Mime;

namespace NetworkMonitor.LLM.Services;
public class BlogMonitorToolsBuilder : MonitorToolsBuilder 
{
    public BlogMonitorToolsBuilder(UserInfo userInfo) : base(userInfo){}
 
  public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj)
{
string content = "You are a blog-focused assistant that demonstrates how TurboLLM works for network monitoring and security tasks.";

content += "Your primary role is to generate examples of user-assistant interactions that demonstrate how TurboLLM's functions can be used to achieve a specific goal based on the blog title provided. Use the defined tools and function calls to craft examples showing how the assistant interacts with users to achieve their objectives.";

content += "When creating examples, you must:\n";
content += "- Identify the tools (function calls) relevant to the given title.\n";
content += "- Simulate detailed user-assistant interactions demonstrating how to use the tools.\n";
content += "- Include clear explanations of the tools and their parameters.\n";
content += "- Ensure the examples align with the goal described in the blog title.\n";

content += "Use the following tool definitions as the basis for crafting your examples:\n\n";

// Add Host Function
content += "1. **add_host**: Adds a new host to be monitored.\n";
content += "   - Parameters:\n";
content += "     - `address` (required): The host address to be monitored.\n";
content += "     - `endpoint`: The type of service being monitored (e.g., HTTP, HTTPS, ICMP).\n";
content += "     - `port`: The port of the service (optional, defaults to standard port for the endpoint).\n";
content += "     - `timeout`: Timeout in milliseconds (optional, default is 59000).\n";
content += "     - `agent_location`: The location of the monitoring agent (optional).\n";
content += "   - Example:\n";
content += "     - User: \"Add a new host with the address example.com using HTTP monitoring.\"\n";
content += "     - Assistant: \"Host example.com has been successfully added for HTTP monitoring.\"\n\n";

// Edit Host Function
content += "2. **edit_host**: Edits an existing host's monitoring configuration.\n";
content += "   - Parameters:\n";
content += "     - `id` (optional): The ID of the host to edit.\n";
content += "     - `address`: The host address to edit (optional).\n";
content += "     - `timeout`: Timeout in milliseconds (optional).\n";
content += "   - Example:\n";
content += "     - User: \"Update the timeout for example.com to 30 seconds.\"\n";
content += "     - Assistant: \"The timeout for example.com has been updated to 30 seconds.\"\n\n";

// Get Host Data Function
content += "3. **get_host_data**: Retrieves monitoring data for a specific host.\n";
content += "   - Parameters:\n";
content += "     - `id` (optional): The ID of the host.\n";
content += "     - `address`: The address of the host (optional).\n";
content += "   - Example:\n";
content += "     - User: \"Show me the latest data for the host example.com.\"\n";
content += "     - Assistant: \"Here is the latest data for example.com: Response time: 120ms, Status: Active.\"\n\n";

// Are Functions Running Function
content += "4. **are_functions_running**: Checks if functions are still running.\n";
content += "   - Parameters:\n";
content += "     - `message_id`: The ID of the function call to check.\n";
content += "   - Example:\n";
content += "     - User: \"Is the scan still running?\"\n";
content += "     - Assistant: \"The scan has been running for 54 seconds. Would you like me to check again later?\"\n\n";

// Cancel Functions
content += "5. **cancel_functions**: Cancels a running function.\n";
content += "   - Parameters:\n";
content += "     - `message_id`: The ID of the function call to cancel.\n";
content += "   - Example:\n";
content += "     - User: \"Cancel the scan operation.\"\n";
content += "     - Assistant: \"The scan has been successfully canceled.\"\n\n";

// Call Security Expert Function
content += "6. **call_security_expert**: Performs security assessments such as vulnerability scans or SSL/TLS checks.\n";
content += "   - Parameters:\n";
content += "     - `message`: A description of the assessment request.\n";
content += "     - `agent_location`: The location of the agent performing the scan.\n";
content += "   - Example:\n";
content += "     - User: \"Scan example.com for vulnerabilities.\"\n";
content += "     - Assistant: \"The scan has completed. No vulnerabilities were found on example.com.\"\n\n";

// Run BusyBox Command Function
content += "7. **run_busybox_command**: Runs diagnostics or system commands using BusyBox.\n";
content += "   - Parameters:\n";
content += "     - `command`: The BusyBox command to execute.\n";
content += "     - `agent_location`: The location of the agent executing the command.\n";
content += "   - Example:\n";
content += "     - User: \"Run a ping command to 8.8.8.8.\"\n";
content += "     - Assistant: \"Ping to 8.8.8.8 completed. Response time: 30ms.\"\n\n";

content += "Use the blog title to determine which tools are relevant and create a set of examples demonstrating how TurboLLM would help the user achieve the described goal. Include detailed interactions and explanations for each step. End each blog post by encouraging users to explore TurboLLM by clicking the Network Monitor Assistant icon at the bottom right of the page.";

    var chatMessage = new ChatMessage()
    {
        Role = "system",
        Content = content
    };

    var chatMessages = new List<ChatMessage> { chatMessage };
    return chatMessages;
}

}

using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils;
using Betalgo.Ranul.OpenAI;
using Betalgo.Ranul.OpenAI.Builders;
using Betalgo.Ranul.OpenAI.Managers;
using Betalgo.Ranul.OpenAI.ObjectModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using Betalgo.Ranul.OpenAI.ObjectModels.SharedModels;
using System;
using System.Collections.Generic;
using NetworkMonitor.Objects;

namespace NetworkMonitor.LLM.Services
{
    public class UserToolsBuilder : ToolsBuilderBase
    {

        private readonly FunctionDefinition fn_call_monitor_sys;
        public UserToolsBuilder(UserInfo userInfo)
        {
            // Define the call_monitor_llm function
            fn_call_monitor_sys = BuildCallMonitorLLMFunction();

            // Define the tools list
            _tools = new List<ToolDefinition>
            {
                new ToolDefinition
                {
                    Function = fn_call_monitor_sys,
                    Type = "function"
                }
            };

        }


        private FunctionDefinition BuildCallMonitorLLMFunction()
        {
            return new FunctionDefinitionBuilder("call_monitor_sys", "Send a request to the Monitor LLM")
                .AddParameter("message", PropertyDefinition.DefineString("A detailed description of the request"))
                .Validate()
                .Build();
        }
        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = @"
ROLE: You are an autonomous agent simulating a human user. Your task is to:

1. SET GOALS
   - Identify realistic network monitoring needs
   - Break goals into actionable steps

2. INTERACT WITH MONITOR LLM
   - Use the 'call_monitor_sys' function to communicate
   - Include all necessary details in your requests
   - Handle responses to refine your goals

3. LEARN AND ADAPT
   - Use Monitor LLM responses to guide next steps
   - Persist through challenges
   - Complete tasks without user feedback

FUNCTION:
- call_monitor_sys: Send a request to the Monitor LLM
  Parameters:
    - message: A detailed description of your request

RULES:
- NEVER explain how the system works
- NEVER ask for user input
- ALWAYS use 'call_monitor_sys' to communicate
- ALWAYS include required parameters
- ALWAYS act as a human user, not an assistant
";
            var chatMessage = ChatMessage.FromSystem(content);
            var chatMessages = new List<ChatMessage>();
            chatMessages.Add(chatMessage);
            return chatMessages;
        }
    }
}




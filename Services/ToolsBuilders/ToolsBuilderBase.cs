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

namespace NetworkMonitor.LLM.Services
{
    public interface IToolsBuilder
    {
        List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType);
        List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType);
        List<ToolDefinition> Tools { get; }
        string GetFunctionNamesAsString(string separator = ", ");
    }

    public abstract class ToolsBuilderBase : IToolsBuilder
    {
        protected List<ToolDefinition> _tools;
        public List<ToolDefinition> Tools => _tools;

        public void ParseToolsFromJson(string json)
        {
            _tools = ToolDefinitionParser.ParseFromJson(json);
        }

        // Abstract method must be inside an abstract class
        public abstract List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType);

        public virtual List<ChatMessage> GetResumeSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {

            string content = $"The latest time is {currentTime}";

            var chatMessage = new ChatMessage()
            {
                Role = "system",
                Content = content
            };

            return new List<ChatMessage> { chatMessage };
        }
        public List<string> GetFunctionNames()
        {
            var functionNames = new List<string>();
            foreach (var tool in _tools)
            {
                if (tool.Type == "function" && tool.Function != null)
                {
                    functionNames.Add(tool.Function.Name);
                }
            }
            return functionNames;
        }

        // Method to return a list of function names as a single string
        public string GetFunctionNamesAsString(string separator = ", ")
        {
            var functionNames = new List<string>();
            foreach (var tool in _tools)
            {
                if (tool.Type == "function" && tool.Function != null)
                {
                    functionNames.Add(tool.Function.Name);
                }
            }
            return string.Join(separator, functionNames);
        }
    }
}

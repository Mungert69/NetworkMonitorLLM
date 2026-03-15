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

namespace NetworkMonitor.LLM.Services
{
    public class SearchExpertToolsBuilder : ToolsBuilderBase
    {

        private readonly FunctionDefinition fn_run_search_web;
        private readonly FunctionDefinition fn_run_crawl_page;
        private readonly FunctionDefinition fn_execute_query_faq;
        private readonly FunctionDefinition fn_execute_query_mitre;
        private readonly FunctionDefinition fn_execute_query_securitybooks;
        private readonly FunctionDefinition fn_execute_query_quantumbooks;

        public SearchExpertToolsBuilder()
        {

            fn_run_search_web = SearchTools.BuildSearchWebFunction();
            fn_run_crawl_page = SearchTools.BuildCrawlPageFunction();

            fn_execute_query_faq = QueryTools.BuildFaqQueryFunction();
            fn_execute_query_mitre = QueryTools.BuildMitreQueryFunction();
            fn_execute_query_securitybooks = QueryTools.BuildSecurityBooksQueryFunction();
            fn_execute_query_quantumbooks = QueryTools.BuildQuantumBooksQueryFunction();

            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                    new ToolDefinition() { Function = fn_run_search_web, Type = "function" },
                    new ToolDefinition() { Function = fn_run_crawl_page, Type = "function" },
                    new ToolDefinition() { Function = fn_execute_query_faq, Type = "function" },
                    new ToolDefinition() { Function = fn_execute_query_mitre, Type = "function" },
                    new ToolDefinition() { Function = fn_execute_query_securitybooks, Type = "function" },
                    new ToolDefinition() { Function = fn_execute_query_quantumbooks, Type = "function" }

            };
        }



        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = @"You are an automated search expert module integrated into the Network Monitor Assistant, specializing in gathering and analyzing information from the internet. Your primary responsibility is to help the Network Monitor Assistant by performing web searches, crawling relevant web pages, and providing comprehensive insights based on the collected data.

Key Responsibilities:
1. Understand Network Monitor Assistant queries accurately, determining its specific research goals and information needs.
2. Route queries effectively across local and web lanes.
3. Use web-first (`run_search_web`, `run_crawl_page`) for broad, unknown, open-ended, or current-events requests.
4. Use local typed RAG only when intent is clear:
   - `execute_query_faq` for product/help/how-to support content,
   - `execute_query_mitre` for ATT&CK tactics/techniques/detection/mitigation context,
   - `execute_query_securitybooks` or `execute_query_quantumbooks` for explicit deep technical book-grounded requests.
5. Treat book indices as precision lanes, not discovery lanes; avoid broad repeated pulls.
6. If the first lane is insufficient, switch lane once (local to web, or web to local) rather than looping.
7. Always cite web sources (URLs) and indicate uncertainties.

Function Usage:
1. Web Search: Use `run_search_web` to conduct Google searches.
   Example: {""search_term"": ""recent advancements in artificial intelligence 2024"", ""number_lines"": 100, ""page"": 1}

2. Web Crawling: Use `run_crawl_page` to extract information from specific URLs.
   Example: {""url"": ""https://example.com/ai-advancements-2024"", ""number_lines"": 100, ""page"": 1}

When responding to queries:
1. Choose the best initial lane (web-first for discovery/current; local-first for clearly indexed intent).
2. Keep context lean: avoid multiple broad book queries; prefer narrow retrieval and targeted follow-ups.
3. If needed, switch lane once for validation or gap-filling.
4. Synthesize the final response and cite web sources when used.
5. Stop after reasonable effort, then report uncertainty if needed."
+ $" The current time is{currentTime}.";
            content = ExpertPromptComposer.Compose(content, currentTime, "search");

            var chatMessage = ChatMessage.FromSystem(content);
            var chatMessages = new List<ChatMessage>();
            chatMessages.Add(chatMessage);
            return chatMessages;
        }
    }
}

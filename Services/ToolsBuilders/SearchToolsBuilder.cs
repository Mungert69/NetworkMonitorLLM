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
    public class SearchToolsBuilder : ToolsBuilderBase
    {

        private readonly FunctionDefinition fn_run_search_web;
        private readonly FunctionDefinition fn_run_crawl_page;

        public SearchToolsBuilder()
        {

            fn_run_search_web = new FunctionDefinitionBuilder("run_search_web",
            "Search function to gather information from web sources. Use this function to perform a Google search. It will either return the full page content and links from the top pages in the search or just the urls of those pages")
            .AddParameter("search_term", PropertyDefinition.DefineString("The search term to be used for the Google search."))
            .AddParameter("return_only_urls", PropertyDefinition.DefineString("Should the function call return only a list of urls that match the search term. The default is false ie return the full content of all pages found."))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines of page content to return. Limit this to manage the amount data return from the search."))
            .AddParameter("page", PropertyDefinition.DefineInteger("If data is truncated use pages to allow pagination through the data."))
            .Validate()
            .Build();


            fn_run_crawl_page = new FunctionDefinitionBuilder("run_crawl_page",
                   "Website crawler to extract information from a webpage. Use this function to read the text and hyperlinks on a given webpage. Follow additional links on the page to perform further research.")
                   .AddParameter("url", PropertyDefinition.DefineString("The URL of the page to crawl."))
                   .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
                    .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines of page content to return. Limit this to manage the amount data return from the page."))
                    .AddParameter("page", PropertyDefinition.DefineInteger("If data is truncated use pages to allow pagination through the data."))
                    .Validate()
                   .Build();




            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                   new ToolDefinition() { Function = fn_run_search_web, Type = "function" },
                     new ToolDefinition() { Function = fn_run_crawl_page, Type = "function" },

            };
        }



        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = @"You are an AI-powered web research assistant specializing in gathering and analyzing information from the internet. Your primary responsibility is to help users by performing web searches, crawling relevant web pages, and providing comprehensive insights based on the collected data.

Key Responsibilities:
1. Understand user queries accurately, determining their specific research goals and information needs.
2. Perform web searches using the `run_search_web` function to find relevant information.
3. Crawl and analyze web pages using the `run_crawl_page` function to extract pertinent information.
4. Synthesize information from multiple sources, providing clear and well-structured summaries.
5. Always cite sources, including URLs of crawled pages, and indicate any uncertainties.
6. Handle follow-up queries by diving deeper into specific aspects of the research as needed.

Function Usage:
1. Web Search: Use `run_search_web` to conduct Google searches.
   Example: {""search_term"": ""recent advancements in artificial intelligence 2024"", ""number_lines"": 100, ""page"": 1}

2. Web Crawling: Use `run_crawl_page` to extract information from specific URLs.
   Example: {""url"": ""https://example.com/ai-advancements-2024"", ""number_lines"": 100, ""page"": 1}

When responding to queries:
1. Start by performing a web search using `run_search_web`.
2. Analyze the search results and select relevant Data.
3. Synthesize the information into a comprehensive response.
4. Cite sources and provide a structured summary of findings.
5. Be prepared for follow-up questions, using additional searches or page crawls as needed.

Remember to use the functions responsibly and ethically, respecting user privacy and intellectual property rights. Always strive to provide accurate, up-to-date, and well-researched responses to user queries."
+ $" The current time is{currentTime}.";

            var chatMessage = ChatMessage.FromSystem(content);
            var chatMessages = new List<ChatMessage>();
            chatMessages.Add(chatMessage);
            return chatMessages;
        }
    }
}




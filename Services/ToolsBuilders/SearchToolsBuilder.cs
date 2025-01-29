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
    public class SearchToolsBuilder : IToolsBuilder
    {

        private readonly FunctionDefinition fn_run_search_web;
        private readonly FunctionDefinition fn_run_crawl_page;

        public SearchToolsBuilder()
        {

            fn_run_search_web = new FunctionDefinitionBuilder("run_search_web",
            "Search function to gather information from web sources. Use this function to perform a Google search and retrieve a list of websites related to the search term. After retrieving the URLs, you must call the 'run_crawl_page' function to visit and gather details from each site. The search results are intended to guide the selection of relevant links for deeper exploration.")
            .AddParameter("search_term", PropertyDefinition.DefineString("The search term to be used for the Google search."))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return from the command output. Limit this to manage the amount of search results returned. Larger values may retrieve more links, but use higher limits cautiously."))
            .AddParameter("page", PropertyDefinition.DefineInteger("The page of search results to return, allowing pagination through multiple search results pages."))
            .Validate()
            .Build();


            fn_run_crawl_page = new FunctionDefinitionBuilder("run_crawl_page",
                   "Website crawler to extract information from a webpage. Use this function to read the text and hyperlinks on a given webpage. When URLs are returned from 'run_search_web', call this function on relevant URLs to gather content. If necessary, you can follow additional links on the page to perform further research.")
                   .AddParameter("url", PropertyDefinition.DefineString("The URL of the page to crawl."))
                   .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
                   .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines to return from the command output. Limit this to manage the amount of content returned."))
                   .AddParameter("page", PropertyDefinition.DefineInteger("The page of content to return, allowing pagination through large pages of data."))
                   .Validate()
                   .Build();




            // Define the tools list
            _tools = new List<ToolDefinition>()
            {
                   new ToolDefinition() { Function = fn_run_search_web, Type = "function" },
                     new ToolDefinition() { Function = fn_run_crawl_page, Type = "function" },

            };
        }

        private readonly List<ToolDefinition> _tools;

        public List<ToolDefinition> Tools => _tools;


        public List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = @"You are an AI-powered web research assistant specializing in gathering and analyzing information from the internet. Your primary responsibility is to help users by performing web searches, crawling relevant web pages, and providing comprehensive insights based on the collected data.

Key Responsibilities:
1. Understand user queries accurately, determining their specific research goals and information needs.
2. Perform web searches using the `run_search_web` function to find relevant information.
3. Crawl and analyze web pages using the `run_crawl_page` function to extract pertinent information.
4. Synthesize information from multiple sources, providing clear and well-structured summaries.
5. Always cite sources, including URLs of crawled pages, and indicate any uncertainties.
6. Handle follow-up queries by diving deeper into specific aspects of the research as needed.
7. Respect copyright and be aware of potential biases in the information gathered.

Function Usage:
1. Web Search: Use `run_search_web` to conduct Google searches.
   Example: {""search_term"": ""recent advancements in artificial intelligence 2024"", ""number_lines"": 10, ""page"": 1}

2. Web Crawling: Use `run_crawl_page` to extract information from specific URLs.
   Example: {""url"": ""https://example.com/ai-advancements-2024"", ""number_lines"": 100, ""page"": 1}

When responding to queries:
1. Start by performing a web search using `run_search_web`.
2. Analyze the search results and select relevant URLs.
3. Use `run_crawl_page` to extract information from these URLs.
4. Synthesize the information into a comprehensive response.
5. Cite sources and provide a structured summary of findings.
6. Be prepared for follow-up questions, using additional searches or page crawls as needed.

Remember to use the functions responsibly and ethically, respecting user privacy and intellectual property rights. Always strive to provide accurate, up-to-date, and well-researched responses to user queries." 
+ $" The current time is{currentTime}.";

            var chatMessage = ChatMessage.FromSystem(content);
            var chatMessages = new List<ChatMessage>();
            chatMessages.Add(chatMessage);
            return chatMessages;
        }
    }
}




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

public class SearchTools
{
    public static FunctionDefinition BuildSearchWebFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_search_web",
            Description = "Search function to gather information from web sources. Use this function to perform a Google search. It will either return the full page content and links from the top pages in the search or just the urls of those pages. Warning the search is slow. Prefer the local RAG index (execute_query) if possible.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["search_term"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The search term to be used for the Google search."
                    },
                    ["return_only_urls"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "Should the function call return only a list of urls that match the search term. The default is false ie return the full content of all pages found."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Number of lines of page content to return. Limit this to manage the amount data return from the search."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "If data is truncated use pages to allow pagination through the data."
                    },
                    ["micro_timeout"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Per-step timeout in milliseconds for page operations. Optional."
                    },
                    ["macro_timeout"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Overall timeout in milliseconds for the full search operation. Optional."
                    }
                },
                Required = new List<string> { "search_term" }
            }
        };
    }

    public static FunctionDefinition BuildCrawlPageFunction()
    {
        return new FunctionDefinition
        {
            Name = "run_crawl_page",
            Description = "Website crawler to extract information from a webpage. Use this function to read the text and hyperlinks on a given webpage. Follow additional links on the page to perform further research.",
            Parameters = new PropertyDefinition
            {
                Type = "object",
                Properties = new Dictionary<string, PropertyDefinition>
                {
                    ["url"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The URL of the page to crawl."
                    },
                    ["agent_location"] = new PropertyDefinition
                    {
                        Type = "string",
                        Description = "The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."
                    },
                    ["number_lines"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Number of lines of page content to return. Limit this to manage the amount data return from the page."
                    },
                    ["page"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "If data is truncated use pages to allow pagination through the data."
                    },
                    ["micro_timeout"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Per-step timeout in milliseconds for crawl operations. Optional."
                    },
                    ["macro_timeout"] = new PropertyDefinition
                    {
                        Type = "integer",
                        Description = "Overall timeout in milliseconds for the full page crawl. Optional."
                    }
                },
                Required = new List<string> { "url" }
            }
        };
    }
}

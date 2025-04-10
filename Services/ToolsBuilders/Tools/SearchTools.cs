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

public class SearchTools {

    public static FunctionDefinition BuildSearchWebFunction()
    {
        return new FunctionDefinitionBuilder("run_search_web",
            "Search function to gather information from web sources. Use this function to perform a Google search. It will either return the full page content and links from the top pages in the search or just the urls of those pages")
            .AddParameter("search_term", PropertyDefinition.DefineString("The search term to be used for the Google search."))
            .AddParameter("return_only_urls", PropertyDefinition.DefineString("Should the function call return only a list of urls that match the search term. The default is false ie return the full content of all pages found."))
            .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
            .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines of page content to return. Limit this to manage the amount data return from the search."))
            .AddParameter("page", PropertyDefinition.DefineInteger("If data is truncated use pages to allow pagination through the data."))
            .Validate()
            .Build();
        }

        public static FunctionDefinition BuildCrawlPageFunction()
    {
        return new FunctionDefinitionBuilder("run_crawl_page",
                   "Website crawler to extract information from a webpage. Use this function to read the text and hyperlinks on a given webpage. Follow additional links on the page to perform further research.")
                   .AddParameter("url", PropertyDefinition.DefineString("The URL of the page to crawl."))
                   .AddParameter("agent_location", PropertyDefinition.DefineString("The agent location that will execute the command, optional. Specify which agent will perform the operation if relevant."))
                    .AddParameter("number_lines", PropertyDefinition.DefineInteger("Number of lines of page content to return. Limit this to manage the amount data return from the page."))
                    .AddParameter("page", PropertyDefinition.DefineInteger("If data is truncated use pages to allow pagination through the data."))
                    .Validate()
                   .Build();
        
        }
}
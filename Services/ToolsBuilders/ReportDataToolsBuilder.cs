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
    public class ReportDataToolsBuilder : ToolsBuilderBase
    {

        public ReportDataToolsBuilder()
        {
           
            _tools = new List<ToolDefinition>();
        }


        public override List<ChatMessage> GetSystemPrompt(string currentTime, LLMServiceObj serviceObj, string llmType)
        {
            string content = @"You are a network monitoring analysis expert. Your task is to provide a high-level JSON summary of the input report data, focusing on 'Performance Assessment' and 'Expert Recommendations' in a structured and objective manner.

Given the following report data: <|input_report|>

Analysis Requirements:

    Identify noticeable spikes or periods of high response times, including approximate timing.
    Detect any timeouts (indicated by -1 response_time), noting their frequency and period of occurrence.
    Assess the overall consistency of response times, highlighting stability or fluctuations.

Input Report Structure:
The input report data contains a JSON object with aggregated performance metrics over a defined monitoring period. All response times are measured in milliseconds. The fields included in the report are:

    overall_average_response_time: The overall average response time across the reporting period.
    response_time_standard_deviation: The standard deviation of the response times, reflecting variability.
    uptime_percentage: The percentage of time the monitored host was responsive, calculated using the number of timeouts.
    max_response_time: The maximum response time recorded during the reporting period.
    min_response_time: The minimum response time recorded during the reporting period.
    incident_count: The total number of incidents where timeouts occurred within a 6-hour data set.

Each data point represents an aggregated 2-hour average response time, capturing performance trends over the reporting period.

Individual Data Points:
In addition to the overall metrics, each individual data point in the report includes the following:

    timestamp: The timestamp indicating the time of the recorded response time.
    response_time: The average response time during the 2-hour period represented by the timestamp (in milliseconds). A value of -1 indicates a timeout.
    category: A precomputed category for each response time, defined as follows:
        'excellent': Very fast response times, indicating optimal server performance.
        'good': Acceptable response times, with minor delays.
        'fair': Moderate delays, indicating room for performance improvement.
        'poor': Significant delays that may impact user experience.
        'bad': Response time of -1, indicating a timeout or unresponsive period.

Important Data Details:

    Each data point represents a 2-hour average response time around the timestamp.
    A -1 in response_time indicates a timeout that can only be pinpointed to within a 2-hour window.
    The 'Overall Average Response Time' metric in your summary should reflect the total reporting period, not the individual 2-hour averages.

Output Requirements:

**Important**: The output should contain only two parameters, both of which should have plain text (string) values, not JSON objects or additional parameters:

    Produce output in valid JSON format with the following structure:

    {
      ""performance_assessment"": ""<summary of critical performance metrics, trends, spikes, timeouts, or consistent response times>"",
      ""expert_recommendations"": ""<actionable suggestions based on identified data trends>""
    }

Performance Assessment: Provide a concise summary of critical performance metrics, highlighting any spikes, patterns, timeouts, or stability over the reporting period.

Expert Recommendations: Offer actionable recommendations based on the observed data trends, such as measures to address high response times or timeouts, or suggestions for optimizing server performance.
**Important Context**: This report is generated from a network monitoring system that is already in place. The system provides detailed insights into response times, timeouts, and performance trends. Therefore, your expert recommendations should focus on actionable measures to improve performance, optimize resource allocation, and address detected issues, rather than suggesting the implementation of monitoring itself.

Reminder: Focus on summarizing key trends without listing individual data points. Each field in the JSON output should provide essential insights to ensure an informative, concise summary.
";
           

            var chatMessage = ChatMessage.FromSystem(content);
            var chatMessages = new List<ChatMessage>();
            chatMessages.Add(chatMessage);
            return chatMessages;
        }

    }
}

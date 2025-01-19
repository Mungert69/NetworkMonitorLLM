using System;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace NetworkMonitor.LLM.Services
{
    public static class TextNormalizationHelper
    {
        /// <summary>
        /// Normalizes text for TTS by processing Markdown, dates, and special characters.
        /// </summary>
        public static string NormalizeTextForTTS(string input, ILogger logger)
        {
            try
            {
                string normalizedText = input;

                // Step 1: Replace ISO 8601 date-time strings
                normalizedText = ReplaceIsoDates(normalizedText);

                // Step 2: Remove Markdown syntax
                normalizedText = RemoveMarkdownSyntax(normalizedText);

                // Step 3: Replace Markdown headers and links
                normalizedText = ReplaceMarkdownHeadersAndLinks(normalizedText);

                // Step 4: Remove special characters
                normalizedText = RemoveSpecialCharacters(normalizedText);

                // Step 5: Trim and normalize spaces
                normalizedText = NormalizeSpaces(normalizedText);

                // Log the final normalized text
                logger.LogInformation($"Normalized Text: {normalizedText}");
                return normalizedText;
            }
            catch (Exception ex)
            {
                logger.LogError($"Error normalizing text: {ex.Message}");
                return input; // Return the original text if normalization fails
            }
        }

        /// <summary>
        /// Replaces ISO 8601 date-time strings with a human-readable format.
        /// </summary>
        /// <summary>
        /// Replaces ISO 8601 and similar date-time strings with a human-readable format.
        /// </summary>
        private static string ReplaceIsoDates(string input)
        {
            return Regex.Replace(input, @"\b\d{4}-\d{2}-\d{2}(?:T|\s)\d{2}:\d{2}:\d{2}\b", match =>
            {
                if (DateTime.TryParse(match.Value, out var dateTime))
                {
                    return dateTime.ToString("MMMM d, yyyy, 'at' h:mm tt"); // Example: "January 13, 2025, at 5:41 PM"
                }
                return match.Value; // Leave unchanged if parsing fails
            });
        }


        /// <summary>
        /// Removes basic Markdown syntax like asterisks and underscores.
        /// </summary>
        private static string RemoveMarkdownSyntax(string input)
        {
            return input
                .Replace("*", "")
                .Replace("_", "")
                .Replace("`", "")
                .Replace("**", "")
                .Replace("~~", "")
                .Replace("\n", " ")  // Replace line breaks with spaces
                .Replace("\r", " "); // Handle carriage returns
        }

        /// <summary>
        /// Replaces Markdown headers and links with readable equivalents.
        /// </summary>
        private static string ReplaceMarkdownHeadersAndLinks(string input)
        {
            input = Regex.Replace(input, @"^#+\s", "", RegexOptions.Multiline); // Remove headers
            input = Regex.Replace(input, @"!\[.*?\]\(.*?\)", "image", RegexOptions.IgnoreCase); // Replace images
            input = Regex.Replace(input, @"\[.*?\]\((.*?)\)", "link to $1", RegexOptions.IgnoreCase); // Replace links
            return input;
        }

        /// <summary>
        /// Removes non-speakable special characters, keeping essential punctuation.
        /// </summary>
        private static string RemoveSpecialCharacters(string input)
        {
            return Regex.Replace(input, @"[^\w\s.,!?;:'\""“”‘’]", "");
        }

        /// <summary>
        /// Trims excessive whitespace and normalizes to single spaces.
        /// </summary>
        private static string NormalizeSpaces(string input)
        {
            return Regex.Replace(input, @"\s+", " ").Trim();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.Extensions.Logging;

namespace NetworkMonitor.LLM.Services
{
    public sealed class TokenBroadcasterDeepseek_3_2_Exp : TokenBroadcasterBase
    {
        public TokenBroadcasterDeepseek_3_2_Exp(
            ILLMResponseProcessor responseProcessor,
            ILogger logger,
            bool xmlFunctionParsing,
            HashSet<string> ignoreParameters)
            : base(responseProcessor, logger, xmlFunctionParsing, ignoreParameters)
        {
        }

        public override List<(string json, string functionName)> ParseInputForJson(string input)
        {
            var functionCalls = new List<(string json, string functionName)>();
          
            try
            {
                var invokeMatches = Regex.Matches(input, @"<invoke\s+name=""(?<name>[^""]+)""[^>]*>(?<parameters>.*?)</invoke>", RegexOptions.Singleline);
                foreach (Match match in invokeMatches)
                {
                    var functionName = match.Groups["name"].Value.Trim();
                    if (string.IsNullOrEmpty(functionName)) continue;

                    var parametersFragment = match.Groups["parameters"].Value;
                    var parametersDoc = new XmlDocument();
                    parametersDoc.LoadXml($"<parameters>{parametersFragment}</parameters>");
                    var parametersNode = parametersDoc.DocumentElement;
                    if (parametersNode == null) continue;

                    var parametersDictionary = new Dictionary<string, object>();
                    foreach (XmlNode node in parametersNode.ChildNodes)
                    {
                        if (node is not XmlElement element || element.Name != "parameter") continue;
                        var nameAttr = element.GetAttribute("name");
                        if (string.IsNullOrWhiteSpace(nameAttr)) continue;
                        if (_ignoreParameters.Contains(nameAttr)) continue;

                        parametersDictionary[nameAttr] = ConvertParameterValue(element);
                    }

                    parametersDictionary["args_escaped"] = false;
                    var json = Newtonsoft.Json.JsonConvert.SerializeObject(parametersDictionary, Newtonsoft.Json.Formatting.None);
                    functionCalls.Add((json, functionName));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to parse DeepSeek invoke XML: {Input}", input);
            }

            if (functionCalls.Count == 0)
            {
                return base.ParseInputForXml(input);
            }

            return functionCalls;
        }

        private static object ConvertParameterValue(XmlElement element)
        {
            if (element == null) return string.Empty;

            if (element.ChildNodes.Count > 0 && element.ChildNodes.Cast<XmlNode>().All(n => n.NodeType == XmlNodeType.CDATA))
            {
                var builder = new StringBuilder();
                foreach (XmlCDataSection cdata in element.ChildNodes)
                {
                    builder.Append(cdata.Value);
                }
                return builder.ToString();
            }

            var text = element.InnerText?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(text)) return string.Empty;

            if (bool.TryParse(text, out var boolValue)) return boolValue;
            if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var longValue)) return longValue;
            if (double.TryParse(text, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out var doubleValue)) return doubleValue;

            if ((text.StartsWith("{") && text.EndsWith("}")) || (text.StartsWith("[") && text.EndsWith("]")))
            {
                try
                {
                    return Newtonsoft.Json.JsonConvert.DeserializeObject(text) ?? text;
                }
                catch
                {
                    return text;
                }
            }

            return text;
        }
    }
}

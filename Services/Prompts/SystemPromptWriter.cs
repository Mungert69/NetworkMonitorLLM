using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;
using NetworkMonitor.Objects;
using NetworkMonitor.Objects.ServiceMessage;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.LLM.Services.Cache;

namespace NetworkMonitor.LLM.Services;

public interface ISystemPromptWriter
{
    void EnsurePromptFile(LLMServiceObj serviceObj, LLMConfig config);
}

public sealed class SystemPromptWriter : ISystemPromptWriter
{
    private readonly ILogger<SystemPromptWriter> _logger;
    private readonly IToolsBuilderFactory _toolsBuilderFactory;
    private readonly IHostEnvironment _hostEnvironment;
    private readonly SystemParams _systemParams;
    private readonly MLParams _mlParams;
    private readonly IRemoteCacheServiceFactory _remoteCacheFactory;
    private readonly RemoteCacheConfig _cacheConfig;

    public SystemPromptWriter(
        ILogger<SystemPromptWriter> logger,
        IToolsBuilderFactory toolsBuilderFactory,
        IHostEnvironment hostEnvironment,
        SystemParams systemParams,
        MLParams mlParams,
        IRemoteCacheServiceFactory remoteCacheFactory)
    {
        _logger = logger;
        _toolsBuilderFactory = toolsBuilderFactory;
        _hostEnvironment = hostEnvironment;
        _systemParams = systemParams;
        _mlParams = mlParams;
        _remoteCacheFactory = remoteCacheFactory ?? throw new ArgumentNullException(nameof(remoteCacheFactory));
        _cacheConfig = mlParams.RemoteCache;
    }

    public void EnsurePromptFile(LLMServiceObj serviceObj, LLMConfig config)
    {
        _logger.LogInformation(
            "SystemPromptWriter invoked for service {ServiceId}, runner {RunnerType}, version {Version}",
            _systemParams.ServiceID,
            serviceObj.LLMRunnerType,
            _mlParams.LlmVersion);
        if (string.IsNullOrWhiteSpace(config.SystemMessageTemplate))
        {
            _logger.LogWarning("SystemMessageTemplate is empty; skipping prompt generation.");
            return;
        }

        string toolsId = serviceObj.ToolsDefinitionId ?? _systemParams.ServiceID ?? "monitor";
        bool enableAgentFlow = _mlParams.EnableAgentFlow;
        IToolsBuilder toolsBuilder = _toolsBuilderFactory.Create(
            toolsId,
            serviceObj.JsonToolsBuilderSpec,
            enableAgentFlow);

        string toolsJson = BuildToolsJsonForPrompt(toolsBuilder.Tools);
        if (string.IsNullOrWhiteSpace(toolsJson))
        {
            toolsJson = "[]";
        }

        string functionDefs = string.IsNullOrWhiteSpace(config.FunctionDefsWrap)
            ? string.Empty
            : string.Format(config.FunctionDefsWrap, toolsJson);

        string promptFooter = _mlParams.XmlFunctionParsing
            ? config.XmlPromptFooter ?? string.Empty
            : config.PromptFooter ?? string.Empty;

        string currentTime = serviceObj.GetClientStartTime().ToString("yyyy-MM-ddTHH:mm:ss");
        var systemMessages = toolsBuilder.GetSystemPrompt(currentTime, serviceObj, serviceObj.LLMRunnerType)
            ?? new List<ChatMessage> { ChatMessage.FromSystem("") };

        if (systemMessages.Count == 0)
        {
            systemMessages.Add(ChatMessage.FromSystem(""));
        }

        if (string.IsNullOrWhiteSpace(systemMessages[0].Content))
        {
            systemMessages[0].Content = LoadBasePrompt(toolsId);
        }

        string suffixPrompt = LoadOptionalPrompt($"system_prompt_suffix_{_mlParams.LlmVersion}");
        systemMessages[0].Content = JoinSections(
            systemMessages[0].Content ?? string.Empty,
            functionDefs ?? string.Empty,
            promptFooter ?? string.Empty,
            suffixPrompt ?? string.Empty);

        var promptMessages = new List<ChatMessage>();
        promptMessages.AddRange(systemMessages);

        string renderedPrompt = PromptRenderer.RenderPromptMessages(config, promptMessages);
        string cacheTail = BuildDefaultCacheTail(config);
        string staticShots = BuildStaticNShots(config, currentTime, serviceObj, toolsId) ?? string.Empty;
        string basePrompt = EnsureTrailingNewline(JoinSections(
            RemoveTrailingToken(renderedPrompt, config),
            JoinStaticShotsAndTail(staticShots, cacheTail, config)));
        string runPrompt = AppendRunToken(basePrompt, config);

        string runPromptName = _mlParams.LlmSystemPrompt;
        string basePromptName = DeriveBasePromptName(runPromptName);

        string runPromptPath = Path.Combine(_mlParams.LlmModelPath, runPromptName);
        string basePromptPath = Path.Combine(_mlParams.LlmModelPath, basePromptName);

        WritePromptIfChanged(basePromptPath, basePrompt);
        WritePromptIfChanged(runPromptPath, runPrompt);

        EnsurePromptCache(basePromptPath, basePrompt, basePromptName, config);
    }

    private string LoadBasePrompt(string toolsId)
    {
        string root = _hostEnvironment.ContentRootPath;
        string normalizedId = toolsId.ToLowerInvariant();
        string specificPath = Path.Combine(root, $"system_prompt_base_{normalizedId}");
        string defaultPath = Path.Combine(root, "system_prompt_base");

        if (File.Exists(specificPath))
        {
            return File.ReadAllText(specificPath).Trim();
        }

        if (File.Exists(defaultPath))
        {
            return File.ReadAllText(defaultPath).Trim();
        }

        return "You are a helpful assistant with access to tools. Use them when needed.";
    }

    private string LoadOptionalPrompt(string fileName)
    {
        string root = _hostEnvironment.ContentRootPath;
        string filePath = Path.Combine(root, fileName);
        return File.Exists(filePath) ? File.ReadAllText(filePath).Trim() : string.Empty;
    }

    private static string JoinSections(params string[] sections)
    {
        return string.Join("\n\n", sections.Where(section => !string.IsNullOrWhiteSpace(section)));
    }

    private static string BuildToolsJsonForPrompt(List<ToolDefinition> tools)
    {
        if (tools == null || tools.Count == 0)
        {
            return string.Empty;
        }

        var toolJsonList = tools
            .Where(tool => tool?.Function != null)
            .Select(tool => new
            {
                name = tool!.Function!.Name,
                description = tool.Function.Description,
                parameters = new
                {
                    type = "object",
                    properties = tool.Function.Parameters?.Properties?
                        .Where(param => param.Value != null)
                        .ToDictionary(
                            param => param.Key,
                            param => (object)new
                            {
                                type = param.Value.Type,
                                description = param.Value.Description
                            })
                        ?? new Dictionary<string, object>(),
                    required = tool.Function.Parameters?.Required?.Count > 0
                        ? tool.Function.Parameters.Required
                        : null
                }
            })
            .ToList();

        return JsonConvert.SerializeObject(
            toolJsonList,
            Formatting.Indented,
            new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
    }

    private void WritePromptIfChanged(string path, string content)
    {
        try
        {
            if (File.Exists(path))
            {
                string existing = File.ReadAllText(path);
                if (string.Equals(existing, content, StringComparison.Ordinal))
                {
                    return;
                }
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
            File.WriteAllText(path, content);
            _logger.LogInformation("Wrote system prompt to {PromptPath}", path);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write system prompt to {PromptPath}", path);
        }
    }

    private void EnsurePromptCache(string basePromptPath, string basePrompt, string basePromptName, LLMConfig config)
    {
        if (string.IsNullOrWhiteSpace(_mlParams.LlmContextFileName))
        {
            _logger.LogWarning("LlmContextFileName is empty; skipping prompt cache build.");
            return;
        }

        string baseContextFileName = GetBaseContextFileName(_mlParams.LlmContextFileName);
        string promptHash = HashHelper.ComputeSha256Hash(basePrompt);
        string hashedContextFileName = BuildHashedContextFileName(baseContextFileName, promptHash);
        _mlParams.LlmContextFileName = hashedContextFileName;
        string contextPath = Path.Combine(_mlParams.LlmModelPath, hashedContextFileName);

        _logger.LogInformation(
            "Prompt cache target resolved. BasePrompt={BasePrompt} Hash={Hash} BaseContextFile={BaseContextFile} ContextFile={ContextFile}",
            basePromptName,
            promptHash,
            baseContextFileName,
            contextPath);

        // Check if context file exists locally
        if (File.Exists(contextPath))
        {
            _logger.LogInformation("Prompt cache already exists locally: {ContextFile}", contextPath);

            // If remote cache is enabled, ensure it's uploaded
            if (_cacheConfig.Enabled && _cacheConfig.Type == "Http")
            {
                try
                {
                    var remoteCache = _remoteCacheFactory.CreateService();
                    if (!remoteCache.HasContextFileAsync(baseContextFileName, promptHash).GetAwaiter().GetResult())
                    {
                        _logger.LogInformation("Remote cache missing; uploading local context file: {ContextFileName}", baseContextFileName);
                        byte[] fileData = File.ReadAllBytes(contextPath);
                        remoteCache.UploadContextFileAsync(baseContextFileName, promptHash, fileData).GetAwaiter().GetResult();
                        _logger.LogInformation("Successfully uploaded local context file to remote cache: {ContextFileName}", baseContextFileName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error syncing local context file to remote cache");
                }
            }

            return;
        }

        // Check remote cache before expensive operation
        if (_cacheConfig.Enabled && _cacheConfig.Type == "Http")
        {
            try
            {
                _logger.LogInformation("Checking remote cache for context file: {ContextFileName}", baseContextFileName);
                
                var remoteCache = _remoteCacheFactory.CreateService();
                if (remoteCache.HasContextFileAsync(baseContextFileName, promptHash).GetAwaiter().GetResult())
                {
                    _logger.LogInformation("Found context file in remote cache, downloading...");
                    
                byte[] fileData = remoteCache.DownloadContextFileAsync(baseContextFileName, promptHash).GetAwaiter().GetResult();
                if (fileData != null && fileData.Length > 0)
                {
                    File.WriteAllBytes(contextPath, fileData);
                    _logger.LogInformation("Successfully downloaded context file from remote cache: {ContextFile}", contextPath);
                    return;
                }
                    else
                    {
                        _logger.LogWarning("Failed to download context file from remote cache");
                    }
                }
                else
                {
                    _logger.LogInformation("Context file not found in remote cache");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking remote cache, falling back to local build");
            }
        }

        // Only do expensive operation if cache is not available
        var startInfo = BuildFallbackStartInfo(basePromptPath, contextPath, config);
        int promptEotCount = CountOccurrences(basePrompt, config.EOTToken);
        _logger.LogInformation(
            "Starting prompt cache build. EOTToken={EotToken} ExpectedEOTCount={EotCount} TimeoutSeconds={TimeoutSeconds}",
            config.EOTToken ?? string.Empty,
            promptEotCount,
            _mlParams.LlmSystemPromptTimeout);
        
        bool buildSuccess = RunPromptCacheCommand(startInfo, config, promptEotCount, contextPath);
        
        // Upload to cache after successful build
        if (buildSuccess && _cacheConfig.Enabled && _cacheConfig.Type == "Http")
        {
            try
            {
                _logger.LogInformation("Uploading context file to remote cache...");
                byte[] fileData = File.ReadAllBytes(contextPath);
                
                var remoteCache = _remoteCacheFactory.CreateService();
                remoteCache.UploadContextFileAsync(baseContextFileName, promptHash, fileData).GetAwaiter().GetResult();
                _logger.LogInformation("Successfully uploaded context file to remote cache: {ContextFileName}", baseContextFileName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error uploading to remote cache");
            }
        }
    }

    private bool RunPromptCacheCommand(ProcessStartInfo startInfo, LLMConfig config, int promptEotCount, string contextPath)
    {
        try
        {
            _logger.LogInformation("Building prompt cache with command: {FileName} {Arguments}", startInfo.FileName, startInfo.Arguments);

            using var process = new Process { StartInfo = startInfo };
            process.Start();
            var timeoutMs = Math.Max(1000, _mlParams.LlmSystemPromptTimeout * 1000);
            var eotToken = config.EOTToken ?? string.Empty;
            var stdoutBuilder = new System.Text.StringBuilder();
            var stderrBuilder = new System.Text.StringBuilder();

            var readTask = Task.Run(async () =>
            {
                var buffer = new char[1024];
                while (!process.HasExited)
                {
                    int read = await process.StandardOutput.ReadAsync(buffer, 0, buffer.Length);
                    if (read <= 0)
                    {
                        await Task.Delay(50);
                        continue;
                    }

                    stdoutBuilder.Append(buffer, 0, read);
                    if (!string.IsNullOrEmpty(eotToken))
                    {
                        int totalEot = CountOccurrences(stdoutBuilder.ToString(), eotToken);
                        if (totalEot > promptEotCount)
                        {
                            _logger.LogInformation("Prompt cache build detected EOT after prompt output; stopping cache process.");
                            try
                            {
                                ProcessSignalHelper.SendCtrlCSignal(process);
                            }
                            catch
                            {
                                // Best effort to stop.
                            }
                            break;
                        }
                    }
                }
            });
            var readErrorTask = Task.Run(async () =>
            {
                var buffer = new char[1024];
                while (!process.HasExited)
                {
                    int read = await process.StandardError.ReadAsync(buffer, 0, buffer.Length);
                    if (read <= 0)
                    {
                        await Task.Delay(50);
                        continue;
                    }

                    stderrBuilder.Append(buffer, 0, read);
                }
            });

            if (!process.WaitForExit(timeoutMs))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Best effort cleanup.
                }
                _logger.LogWarning("Prompt cache build timed out after {TimeoutMs}ms.", timeoutMs);
                return File.Exists(contextPath);
            }

            readTask.Wait(TimeSpan.FromSeconds(2));
            readErrorTask.Wait(TimeSpan.FromSeconds(2));
            if (process.ExitCode != 0)
            {
                string output = stdoutBuilder.Length > 0 ? stdoutBuilder.ToString() : process.StandardOutput.ReadToEnd();
                string error = stderrBuilder.Length > 0 ? stderrBuilder.ToString() : process.StandardError.ReadToEnd();
                _logger.LogWarning("Prompt cache build exited non-zero. ExitCode={ExitCode} Output={Output} Error={Error}", process.ExitCode, output, error);
            }

            string stdout = stdoutBuilder.ToString();
            if (!string.IsNullOrWhiteSpace(stdout))
            {
                _logger.LogDebug("Prompt cache build output: {Output}", stdout);
            }
            string stderr = stderrBuilder.ToString();
            if (!string.IsNullOrWhiteSpace(stderr))
            {
                _logger.LogDebug("Prompt cache build error output: {Output}", stderr);
            }

            if (WaitForStableFile(contextPath, TimeSpan.FromSeconds(90), _logger))
            {
                _logger.LogInformation("Prompt cache build produced cache file: {ContextPath}", contextPath);
                return true;
            }

            _logger.LogWarning("Prompt cache build did not produce cache file: {ContextPath}", contextPath);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Prompt cache build failed.");
            return false;
        }
    }

    private static bool WaitForStableFile(string path, TimeSpan maxWait, ILogger logger)
    {
        var start = DateTime.UtcNow;
        long lastSize = -1;
        int stableCount = 0;
        DateTime lastLog = DateTime.UtcNow;

        while (DateTime.UtcNow - start < maxWait)
        {
            if (File.Exists(path))
            {
                long size = new FileInfo(path).Length;
                if (size > 0 && size == lastSize)
                {
                    stableCount++;
                    if (stableCount >= 2)
                        return true;
                }
                else
                {
                    stableCount = 0;
                }
                lastSize = size;
                if ((DateTime.UtcNow - lastLog) > TimeSpan.FromSeconds(5))
                {
                    logger.LogInformation("Waiting for cache file to stabilize. Path={ContextPath} SizeBytes={SizeBytes}", path, size);
                    lastLog = DateTime.UtcNow;
                }
            }
            else if ((DateTime.UtcNow - lastLog) > TimeSpan.FromSeconds(5))
            {
                logger.LogInformation("Waiting for cache file to appear. Path={ContextPath}", path);
                lastLog = DateTime.UtcNow;
            }

            System.Threading.Thread.Sleep(1000);
        }

        logger.LogWarning("Timed out waiting for cache file to stabilize. Path={ContextPath} LastSizeBytes={SizeBytes}", path, lastSize);
        return File.Exists(path);
    }

    private static int CountOccurrences(string source, string? token)
    {
        if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(token))
        {
            return 0;
        }

        int count = 0;
        int index = 0;
        while ((index = source.IndexOf(token, index, StringComparison.Ordinal)) != -1)
        {
            count++;
            index += token.Length;
        }

        return count;
    }

    private ProcessStartInfo BuildFallbackStartInfo(string basePromptPath, string contextPath, LLMConfig config)
    {
        string llamaPath = $"{_mlParams.LlmModelPath}llama.cpp/llama-completion";
        string reversePrompt = BuildReversePrompt(config);
        string promptMode = SanitizePromptModeForCache(_mlParams.LlmPromptMode ?? string.Empty);
        string modelPath = _mlParams.LlmModelPath + _mlParams.LlmModelFileName;
        string tempValue = "0";
        int threads = Math.Max(1, _mlParams.LlmThreads);
        var args = $"{promptMode} {reversePrompt} -c {_mlParams.LlmCtxSize} -m \"{modelPath}\" --prompt-cache \"{contextPath}\" -f \"{basePromptPath}\" --temp {tempValue} -t {threads} -tb {threads}";

        return new ProcessStartInfo
        {
            FileName = llamaPath,
            Arguments = args,
            WorkingDirectory = _mlParams.LlmModelPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
    }

    private static string BuildReversePrompt(LLMConfig config)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(config.EOTToken))
        {
            parts.Add($"-r \"{config.EOTToken}\"");
        }
        if (!string.IsNullOrWhiteSpace(config.EOMToken))
        {
            parts.Add($"-r \"{config.EOMToken}\"");
        }

        return string.Join(" ", parts);
    }

    private static string DeriveBasePromptName(string runPromptName)
    {
        if (string.IsNullOrWhiteSpace(runPromptName))
        {
            return runPromptName;
        }

        const string suffix = "_run";
        return runPromptName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
            ? runPromptName.Substring(0, runPromptName.Length - suffix.Length)
            : runPromptName + "_base";
    }

    private static string RemoveTrailingToken(string prompt, LLMConfig config)
    {
        if (string.IsNullOrEmpty(prompt))
        {
            return string.Empty;
        }

        string trimmed = prompt.TrimEnd();

        if (!string.IsNullOrWhiteSpace(config.EOTToken) && trimmed.EndsWith(config.EOTToken, StringComparison.Ordinal))
        {
            trimmed = trimmed.Substring(0, trimmed.Length - config.EOTToken.Length).TrimEnd();
        }

        if (!string.IsNullOrWhiteSpace(config.EOMToken) && trimmed.EndsWith(config.EOMToken, StringComparison.Ordinal))
        {
            trimmed = trimmed.Substring(0, trimmed.Length - config.EOMToken.Length).TrimEnd();
        }

        return trimmed;
    }

    private static string AppendRunToken(string prompt, LLMConfig config)
    {
        if (string.IsNullOrEmpty(prompt))
        {
            return string.Empty;
        }

        if (string.IsNullOrWhiteSpace(config.EOTToken))
        {
            return prompt;
        }

        return $"{prompt}{config.EOTToken}\n\n";
    }

    private static string BuildHashedContextFileName(string baseFileName, string promptHash)
    {
        if (string.IsNullOrWhiteSpace(baseFileName))
        {
            return $"context-{promptHash}.gguf";
        }

        string directory = Path.GetDirectoryName(baseFileName) ?? string.Empty;
        string name = Path.GetFileNameWithoutExtension(baseFileName);
        string ext = Path.GetExtension(baseFileName);
        name = StripExistingHashSuffix(name, promptHash);
        string hashedName = $"{name}.{promptHash}{(string.IsNullOrEmpty(ext) ? ".gguf" : ext)}";

        return string.IsNullOrEmpty(directory) ? hashedName : Path.Combine(directory, hashedName);
    }

    private static string StripExistingHashSuffix(string name, string promptHash)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return name;
        }

        int lastDot = name.LastIndexOf('.');
        if (lastDot <= 0 || lastDot == name.Length - 1)
        {
            return name;
        }

        string suffix = name.Substring(lastDot + 1);
        if (suffix.Length == promptHash.Length && suffix.All(c => Uri.IsHexDigit(c)))
        {
            return name.Substring(0, lastDot);
        }

        return name;
    }

    private static string EnsureTrailingNewline(string prompt)
    {
        if (string.IsNullOrEmpty(prompt))
        {
            return string.Empty;
        }

        return prompt.EndsWith("\n", StringComparison.Ordinal) ? prompt : $"{prompt}\n";
    }

    private static string GetBaseContextFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return fileName;
        }

        // If filename already includes a 64-hex hash suffix (e.g., name.<hash>.gguf), strip it.
        var match = System.Text.RegularExpressions.Regex.Match(
            fileName,
            @"^(?<base>.+)\.[0-9a-fA-F]{64}(?<ext>\.[^\.]+)$");

        return match.Success ? $"{match.Groups["base"].Value}{match.Groups["ext"].Value}" : fileName;
    }

    private static string SanitizePromptModeForCache(string promptMode)
    {
        if (string.IsNullOrWhiteSpace(promptMode))
        {
            return string.Empty;
        }

        var tokens = promptMode
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(token => token == "-if" ? "-i" : token)
            .Distinct(StringComparer.Ordinal);

        return string.Join(" ", tokens);
    }

    private static string BuildDefaultCacheTail(LLMConfig config)
    {
        string userTemplate = PromptRenderer.NormalizeTemplate(config.UserInputTemplate);
        string assistantTemplate = PromptRenderer.NormalizeTemplate(config.AssistantMessageTemplate);

        string userPrompt = string.Format(userTemplate, "What's my user info?");

        string toolCall = PromptRenderer.BuildToolCallText(
            config,
            "get_user_info",
            "{\"detail_response\": false}");

        string assistantPrompt = string.Format(assistantTemplate, toolCall);
        assistantPrompt = RemoveTrailingToken(assistantPrompt, config);

        return JoinCacheTail(userPrompt, assistantPrompt, config);
    }

    private static string JoinCacheTail(string userPrompt, string assistantPrompt, LLMConfig config)
    {
        if (string.IsNullOrEmpty(config.EOTToken))
        {
            return $"{userPrompt}{assistantPrompt}";
        }

        string trimmedUser = userPrompt.TrimEnd();
        if (trimmedUser.EndsWith(config.EOTToken, StringComparison.Ordinal))
        {
            return $"{userPrompt}{assistantPrompt}";
        }

        return $"{userPrompt}{config.EOTToken}{assistantPrompt}";
    }

    private static string JoinStaticShotsAndTail(string staticShots, string cacheTail, LLMConfig config)
    {
        if (string.IsNullOrWhiteSpace(staticShots))
        {
            return cacheTail ?? string.Empty;
        }

        if (string.IsNullOrWhiteSpace(cacheTail))
        {
            return staticShots;
        }

        string eotToken = config.EOTToken ?? string.Empty;
        if (!string.IsNullOrEmpty(eotToken)
            && !staticShots.TrimEnd().EndsWith(eotToken, StringComparison.Ordinal))
        {
            return $"{staticShots}{eotToken}\n\n{cacheTail}";
        }

        return $"{staticShots}\n\n{cacheTail}";
    }

    private string BuildStaticNShots(LLMConfig config, string currentTime, LLMServiceObj serviceObj, string toolsId)
    {
        if (_mlParams.NoNShot)
        {
            return string.Empty;
        }

        var staticMessages = NShotPromptFactory.GetStaticPrompt(
            _systemParams.ServiceID ?? toolsId,
            _mlParams.XmlFunctionParsing,
            currentTime,
            serviceObj,
            config);

        return staticMessages.Count == 0
            ? string.Empty
            : RenderCacheMessages(config, staticMessages);
    }

    private static string RenderCacheMessages(LLMConfig config, IReadOnlyList<ChatMessage> messages)
    {
        var builder = new System.Text.StringBuilder();
        string systemTemplate = PromptRenderer.NormalizeTemplate(config.SystemMessageTemplate);
        string userTemplate = PromptRenderer.NormalizeTemplate(config.UserInputTemplate);
        string assistantTemplate = PromptRenderer.NormalizeTemplate(config.AssistantMessageTemplate);
        string functionTemplate = PromptRenderer.NormalizeTemplate(config.FunctionResponseTemplate);
        string eotToken = config.EOTToken ?? string.Empty;

        for (int i = 0; i < messages.Count; i++)
        {
            var message = messages[i];
            if (message == null)
            {
                continue;
            }

            string role = message.Role ?? string.Empty;
            string content = message.Content ?? string.Empty;

            if (role.Equals("system", StringComparison.OrdinalIgnoreCase))
            {
                builder.Append(string.Format(systemTemplate, content));
            }
            else if (role.Equals("user", StringComparison.OrdinalIgnoreCase))
            {
                builder.Append(string.Format(userTemplate, content));
            }
            else if (role.Equals("assistant", StringComparison.OrdinalIgnoreCase))
            {
                string assistantContent = BuildAssistantContentForCache(config, message, content);
                builder.Append(string.Format(assistantTemplate, assistantContent));
            }
            else if (role.Equals("tool", StringComparison.OrdinalIgnoreCase))
            {
                builder.Append(string.Format(functionTemplate, string.Empty, content));
            }

            if (ShouldInsertEotAfterMessage(message, messages, i, eotToken) && !BuilderEndsWith(builder, eotToken))
            {
                builder.Append(eotToken);
            }
        }

        return builder.ToString();
    }

    private static string BuildAssistantContentForCache(LLMConfig config, ChatMessage message, string content)
    {
        var toolCalls = message.ToolCalls;
        if (toolCalls == null || toolCalls.Count == 0)
        {
            return content;
        }

        var toolCallBlocks = new List<string>();
        foreach (var call in toolCalls)
        {
            string name = call.FunctionCall?.Name ?? string.Empty;
            string args = call.FunctionCall?.Arguments ?? "{}";
            string toolCallText = PromptRenderer.BuildToolCallText(config, name, args);
            toolCallBlocks.Add(toolCallText);
        }

        string toolCallsText = string.Join("\n", toolCallBlocks);
        if (string.IsNullOrWhiteSpace(content))
        {
            return toolCallsText;
        }

        return $"{content}\n{toolCallsText}";
    }

    private static bool ShouldInsertEotAfterMessage(ChatMessage current, IReadOnlyList<ChatMessage> messages, int index, string eotToken)
    {
        if (string.IsNullOrEmpty(eotToken))
        {
            return false;
        }

        string role = current.Role ?? string.Empty;
        if (!role.Equals("user", StringComparison.OrdinalIgnoreCase)
            && !role.Equals("tool", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (index + 1 >= messages.Count)
        {
            return false;
        }

        var next = messages[index + 1];
        return next != null && string.Equals(next.Role, "assistant", StringComparison.OrdinalIgnoreCase);
    }

    private static bool BuilderEndsWith(System.Text.StringBuilder builder, string token)
    {
        if (builder.Length < token.Length)
        {
            return false;
        }

        for (int i = 0; i < token.Length; i++)
        {
            if (builder[builder.Length - token.Length + i] != token[i])
            {
                return false;
            }
        }

        return true;
    }
}

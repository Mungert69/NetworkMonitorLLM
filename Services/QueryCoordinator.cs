using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Data.Services;
using Microsoft.Extensions.Logging;
using Betalgo.Ranul.OpenAI.ObjectModels.ResponseModels;
using Betalgo.Ranul.OpenAI.ObjectModels.RequestModels;

namespace NetworkMonitor.LLM.Services
{

    public interface IQueryCoordinator
    {
        Task<string> ExecuteQueryAsync(string queryText, string messageId, string llmType, TimeSpan? timeout = null);
        void CompleteQuery(string messageId, string result);
        void CancelQuery(string messageId);
        void RemoveSystemRag(List<ChatMessage> localHistory);
        Task AddSystemRag(string messageId, List<ChatMessage> localHistory);
    }
    public class QueryCoordinator : IQueryCoordinator
    {
        private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pendingQueries =
            new ConcurrentDictionary<string, TaskCompletionSource<string>>();
        private readonly ConcurrentDictionary<string, string> _userQueries =
            new ConcurrentDictionary<string, string>();


        private readonly TimeSpan _defaultTimeout = TimeSpan.FromSeconds(30); // Default timeout for queries
        private readonly IRabbitRepo _rabbitRepo;
        private readonly string _serviceID;
        private readonly string _authKey;

        private const string SystemRagMessage = "The following RAG data has been added.";

        private readonly ILogger _logger;

        public QueryCoordinator(ILogger<QueryCoordinator> logger, IRabbitRepo rabbitRepo, ISystemParamsHelper systemParamsHelper)
        {
            _logger = logger;
            _rabbitRepo = rabbitRepo;
            _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
            string encryptKey=systemParamsHelper.GetSystemParams().EmailEncryptKey ;
            _authKey=EncryptHelper.EncryptedPassword(encryptKey,_serviceID);

        }

        public async Task AddSystemRag(string messageId, List<ChatMessage> localHistory)
        {
            string ragResult = string.Empty;
            if (_userQueries.TryGetValue(messageId, out var userInput))
            {

                _logger.LogInformation($"Waiting for RAG result for message ID: {messageId}");

                if (_pendingQueries.TryGetValue(messageId, out var tcs))
                {
                    // Wait for the RAG result (if the query is still pending)
                    try
                    {
                        ragResult = await tcs.Task;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error waiting for RAG result for message ID {messageId}: {ex.Message}");
                        return;
                    }
                }
                else
                {
                    _logger.LogWarning($"No pending or completed query found for message ID: {messageId}");
                    return;
                }

                // Add the RAG result as a system message
                if (!string.IsNullOrEmpty(ragResult))
                {
                    var systemMessage = ChatMessage.FromSystem($"{SystemRagMessage} Use it to answer the user's queries : " + ragResult);
                    localHistory.Add(systemMessage);
                    _logger.LogInformation($"RAG result added to chat history: {ragResult}");
                }
                else
                {
                    _logger.LogWarning($"RAG result for message ID {messageId} is empty.");
                }
            }
            else
            {
                _logger.LogWarning($"No user input found for message ID: {messageId}");
            }
        }
        public void RemoveSystemRag(List<ChatMessage> localHistory)
        {
            if (localHistory == null || localHistory.Count == 0)
            {
                _logger.LogWarning("Local history is null or empty. No system message to remove.");
                return;
            }

            // Find the first system message that contains RAG-related content
            var ragSystemMessage = localHistory.FirstOrDefault(m =>
                m.Role == "system" &&
                m.Content != null &&
                m.Content.StartsWith(SystemRagMessage));

            if (ragSystemMessage != null)
            {
                localHistory.Remove(ragSystemMessage);
                _logger.LogInformation("Removed RAG system message from local history.");
            }
            else
            {
                _logger.LogWarning("No RAG system message found in local history.");
            }
        }
        public async Task<string> ExecuteQueryAsync(string queryText, string messageId, string llmType, TimeSpan? timeout = null)
        {
            var tcs = new TaskCompletionSource<string>();
            if (!_pendingQueries.TryAdd(messageId, tcs) || !_userQueries.TryAdd(messageId, queryText))
            {
                _logger.LogWarning($"Message ID {messageId} already exists in pending queries.");
                return string.Empty;
            }


            var cts = new CancellationTokenSource();
            var timeoutTask = Task.Delay(timeout ?? _defaultTimeout, cts.Token)
                .ContinueWith(_ =>
                {
                    if (_pendingQueries.TryGetValue(messageId, out var removedTcs) && !removedTcs.Task.IsCompleted)
                    {
                        removedTcs.TrySetException(new TimeoutException("Query timed out."));
                    }
                }, TaskScheduler.Default);

            // Create the QueryIndexRequest
            var queryIndexRequest = new QueryIndexRequest
            {
                IndexName = "documents",
                QueryText = queryText,
                MessageID = messageId,
                AppID = llmType,
                AuthKey=_authKey
            };

            // Publish the query to RabbitMQ
            await _rabbitRepo.PublishAsync("queryIndex", queryIndexRequest);

            // Wait for the RAG result
            return await tcs.Task;
        }

        public void CompleteQuery(string messageId, string result)
        {
            if (_pendingQueries.TryGetValue(messageId, out var tcs))
            {
                // Set the result on the TaskCompletionSource
                tcs.TrySetResult(result);
                _logger.LogInformation($"RAG result completed for message ID: {messageId}");
            }
            else
            {
                _logger.LogWarning($"No pending query found to complete for message ID: {messageId}");
            }
        }

        public void CancelQuery(string messageId)
        {
            if (_pendingQueries.TryGetValue(messageId, out var tcs))
            {
                tcs.TrySetCanceled();
                _logger.LogInformation($"RAG query canceled for message ID: {messageId}");
            }
            else
            {
                _logger.LogWarning($"No pending query found to cancel for message ID: {messageId}");
            }
        }
    }
}
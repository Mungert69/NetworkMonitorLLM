using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects.Repository;
using NetworkMonitor.Data.Services;

namespace NetworkMonitor.LLM.Services
{

     public interface IQueryCoordinator
    {
        Task<string> ExecuteQueryAsync(string queryText, string messageId, string llmType, TimeSpan? timeout = null);
        void CompleteQuery(string messageId, string result);
        void CancelQuery(string messageId);
    }
    public class QueryCoordinator :  IQueryCoordinator
    {
        private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pendingQueries =
            new ConcurrentDictionary<string, TaskCompletionSource<string>>();

        private readonly TimeSpan _defaultTimeout = TimeSpan.FromSeconds(30); // Default timeout for queries
        private readonly IRabbitRepo _rabbitRepo;
        private readonly string _serviceID;

        public QueryCoordinator(IRabbitRepo rabbitRepo, ISystemParamsHelper systemParamsHelper)
        {
            _rabbitRepo = rabbitRepo;
              _serviceID = systemParamsHelper.GetSystemParams().ServiceID!;
      
        }

        public async Task<string> ExecuteQueryAsync(string queryText, string messageId, string llmType, TimeSpan? timeout = null)
        {
            var tcs = new TaskCompletionSource<string>();
            _pendingQueries[messageId] = tcs;

            // Set a timeout for the query
            var timeoutTask = Task.Delay(timeout ?? _defaultTimeout).ContinueWith(_ =>
            {
                if (_pendingQueries.TryRemove(messageId, out var removedTcs))
                {
                    removedTcs.TrySetException(new TimeoutException("Query timed out."));
                }
            });

            // Create the QueryIndexRequest
            var queryIndexRequest = new QueryIndexRequest
            {
                IndexName="documents",
                QueryText = queryText,
                MessageID = messageId,
                AppID = llmType
            };

            // Publish the query to RabbitMQ
            await _rabbitRepo.PublishAsync("queryIndex" , queryIndexRequest);

            // Wait for the RAG result
            return await tcs.Task;
        }

        public void CompleteQuery(string messageId, string result)
        {
            if (_pendingQueries.TryRemove(messageId, out var tcs))
            {
                tcs.TrySetResult(result);
            }
        }

        public void CancelQuery(string messageId)
        {
            if (_pendingQueries.TryRemove(messageId, out var tcs))
            {
                tcs.TrySetCanceled();
            }
        }
    }
}
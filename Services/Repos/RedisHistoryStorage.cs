using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using StackExchange.Redis;
using NetworkMonitor.Utils.Helpers;
using NetworkMonitor.Objects;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.Repository;

namespace NetworkMonitor.LLM.Services
{
    public class RedisHistoryStorage : IHistoryStorage, IDisposable
    {
        private readonly ConnectionMultiplexer _redis;
        private readonly IDatabase _db;
        private readonly string _keyPrefix;
        private readonly string _indexKey;
        private bool _disposed = false;
        private readonly ILogger _logger;
        private readonly string _serviceId;
        private readonly IRabbitRepo? _rabbitRepo;
        private readonly string _serviceAuthKey;

        public RedisHistoryStorage(ILogger<RedisHistoryStorage> logger, SystemParams systemParams, IRabbitRepo? rabbitRepo = null)
        {
            var configuration = BuildConfiguration(systemParams.RedisUrl, systemParams.RedisSecret);
            _logger = logger;
            _redis = ConnectionMultiplexer.Connect(configuration);
            _db = _redis.GetDatabase();
            _serviceId = SanitizeServiceId(systemParams.ServiceID);
            _serviceAuthKey = systemParams.ServiceAuthKey ?? "Missing";
            _rabbitRepo = rabbitRepo;
            _keyPrefix = $"history:{_serviceId}:";
            _indexKey = $"idx:history:{_serviceId}:all";
        }

        internal static ConfigurationOptions BuildConfiguration(string redisUrl, string redisSecret)
        {
            var config = new ConfigurationOptions
            {
                // Basic connection
                EndPoints = { redisUrl },  // e.g. "your-server:46379"
                Password = redisSecret,
                User = "admin",

                // TLS Configuration
                Ssl = true,
                SslProtocols = System.Security.Authentication.SslProtocols.Tls13,

                // Connection tuning
                ConnectTimeout = 5000,
                SyncTimeout = 5000,
                AbortOnConnectFail = false
            };


            // Remove the handler that ignores SSL certificate errors
            // config.CertificateValidation += (sender, cert, chain, errors) => true;

            // Optionally, you can add stricter validation or leave it to default (which validates certs)
            return config;
        }

        private async Task EnsureIndexSetAsync()
        {
            if (await _db.SetLengthAsync(_indexKey) > 0) return;

            var server = GetServer();
            var keys = await GetKeysAsync(server, $"{_keyPrefix}*"); // full scan *once*
            if (keys.Count == 0) return;

            var indexValues = new List<RedisValue>(keys.Count);
            foreach (var key in keys)
            {
                var keyString = key.ToString();
                if (!string.IsNullOrEmpty(keyString))
                {
                    indexValues.Add((RedisValue)keyString);
                }
            }

            if (indexValues.Count > 0)
            {
                await _db.SetAddAsync(_indexKey, indexValues.ToArray());
            }
        }

        public async Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
        {
            var sessions = new ConcurrentDictionary<string, Session>();

            try
            {
                //await EnsureIndexSetAsync(); /// remove this after first run 

                // 1) Grab your pre‐maintained index of history‐keys:
                var rawKeys = await _db.SetMembersAsync(_indexKey);
                if (rawKeys.Length == 0)
                    return sessions;

                // 2) Convert RedisValue[] to RedisKey[] so we can MGET
                var redisKeysList = new List<RedisKey>(rawKeys.Length);
                foreach (var rawKey in rawKeys)
                {
                    if (!rawKey.HasValue) continue;
                    var keyString = rawKey.ToString();
                    if (string.IsNullOrEmpty(keyString)) continue;
                    redisKeysList.Add((RedisKey)keyString);
                }

                if (redisKeysList.Count == 0)
                    return sessions;

                // 3) MGET all values in one round‐trip
                var rawValues = await _db.StringGetAsync(redisKeysList.ToArray());

                // 4) Deserialize and build your session map
                for (int i = 0; i < redisKeysList.Count; i++)
                {
                    var json = rawValues[i];
                    if (!json.HasValue) continue;

                    var history = JsonConvert
                        .DeserializeObject<HistoryDisplayName>(json.ToString());
                    if (history?.SessionId is null or { Length: 0 }) continue;

                    sessions.TryAdd(
                        history.SessionId,
                        new Session { HistoryDisplayName = history }
                    );
                }
                _logger.LogInformation($"Success : Got {sessions.Count} histories");
                return sessions;
            }
            catch (RedisTimeoutException ex)
            {
                _logger.LogWarning(ex, "Redis timeout while loading histories; continuing without cached sessions.");
                return sessions;
            }
            catch (RedisConnectionException ex)
            {
                _logger.LogWarning(ex, "Redis connection error while loading histories; continuing without cached sessions.");
                return sessions;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unexpected error while loading histories; continuing without cached sessions.");
                return sessions;
            }
        }

        public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId, string? serviceId = null)
        {
            var historyDisplayNames = new List<HistoryDisplayName>();
            var server = GetServer();
            var keyPrefix = GetKeyPrefix(serviceId);
            var keys = await GetKeysAsync(server, $"{keyPrefix}*_{userId}_*");

            foreach (var key in keys)
            {
                try
                {
                    var history = await LoadFromKey(key);
                    if (history != null)
                    {
                        historyDisplayNames.Add(history);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading history from Redis key {key}: {ex.Message}");
                }
            }

            return historyDisplayNames;
        }

        public async Task<HistoryDisplayName?> LoadHistoryAsync(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                throw new ArgumentException("Session ID cannot be empty", nameof(sessionId));

            var server = GetServer();
            var keys = await GetKeysAsync(server, $"{_keyPrefix}*_{sessionId}");

            foreach (var key in keys)
            {
                try
                {
                    return await LoadFromKey(key);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading session {sessionId} from Redis: {ex.Message}");
                }
            }

            return null;
        }



        public async Task SaveHistoryAsync(HistoryDisplayName historyDisplayName)
        {
            if (historyDisplayName == null)
                throw new ArgumentNullException(nameof(historyDisplayName));

            var key = $"{_keyPrefix}{historyDisplayName.StartUnixTime}_{historyDisplayName.SessionId}";
            var json = JsonConvert.SerializeObject(historyDisplayName,
                new JsonSerializerSettings
                {
                    ContractResolver = new CamelCasePropertyNamesContractResolver(),
                    Formatting = Formatting.Indented
                });

            // **atomic**: store the blob and add the key to the index-set
            var tran = _db.CreateTransaction();
            _ = tran.StringSetAsync(key, json);
            _ = tran.SetAddAsync(_indexKey, key);

            await tran.ExecuteAsync().ConfigureAwait(false);

            await PublishMirrorRequestAsync(new HistoryStoreRequest
            {
                Operation = HistoryStoreOperation.upsert,
                AppID = _serviceId,
                AuthKey = _serviceAuthKey,
                ServiceId = _serviceId,
                SessionId = historyDisplayName.SessionId,
                UserId = historyDisplayName.UserId,
                StartUnixTime = historyDisplayName.StartUnixTime,
                Name = historyDisplayName.Name,
                LlmType = historyDisplayName.LlmType,
                HistoryJson = json,
                MessageID = Guid.NewGuid().ToString("N"),
                ResponseExchange = $"{_serviceId}HistoryStoreResult"
            }).ConfigureAwait(false);
        }

        public async Task DeleteHistoryAsync(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                throw new ArgumentException(nameof(sessionId));

            var pattern = $"{_keyPrefix}*_{sessionId}";
            var server = GetServer();
            var keys = await GetKeysAsync(server, pattern);

            if (keys.Count == 0) return;

            var tran = _db.CreateTransaction();
            foreach (var k in keys)
            {
                _ = tran.KeyDeleteAsync(k);
                var keyString = k.ToString();
                if (!string.IsNullOrEmpty(keyString))
                {
                    _ = tran.SetRemoveAsync(_indexKey, (RedisValue)keyString);
                }
            }
            await tran.ExecuteAsync().ConfigureAwait(false);

            await PublishMirrorRequestAsync(new HistoryStoreRequest
            {
                Operation = HistoryStoreOperation.delete,
                AppID = _serviceId,
                AuthKey = _serviceAuthKey,
                ServiceId = _serviceId,
                SessionId = sessionId,
                MessageID = Guid.NewGuid().ToString("N"),
                ResponseExchange = $"{_serviceId}HistoryStoreResult"
            }).ConfigureAwait(false);
        }


        private async Task<HistoryDisplayName?> LoadFromKey(RedisKey key)
        {
            var json = await _db.StringGetAsync(key);
            return json.HasValue
                ? JsonConvert.DeserializeObject<HistoryDisplayName>(json.ToString())
                : null;
        }

        private string GetKeyPrefix(string? serviceId)
        {
            if (string.IsNullOrWhiteSpace(serviceId)) return _keyPrefix;
            var cleaned = SanitizeServiceId(serviceId);
            return $"history:{cleaned}:";
        }

        private string GetIndexKey(string? serviceId)
        {
            if (string.IsNullOrWhiteSpace(serviceId)) return _indexKey;
            var cleaned = SanitizeServiceId(serviceId);
            return $"idx:history:{cleaned}:all";
        }

        private IServer GetServer()
        {
            var endpoints = _redis.GetEndPoints();
            if (endpoints.Length == 0)
                throw new InvalidOperationException("No Redis endpoints available");

            return _redis.GetServer(endpoints.First());
        }

        private async Task<List<RedisKey>> GetKeysAsync(IServer server, string pattern)
        {
            var keys = new List<RedisKey>();
            var enumerator = server.KeysAsync(
                database: _db.Database,
                pattern: pattern,
                pageSize: 100).GetAsyncEnumerator();

            try
            {
                while (await enumerator.MoveNextAsync().ConfigureAwait(false))
                {
                    keys.Add(enumerator.Current);
                }
            }
            finally
            {
                await enumerator.DisposeAsync().ConfigureAwait(false);
            }

            return keys;
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _redis?.Close();
                    _redis?.Dispose();
                }
                _disposed = true;
            }
        }

        private static string SanitizeServiceId(string? serviceId)
        {
            if (string.IsNullOrWhiteSpace(serviceId)) return "default";
            var invalidChars = System.IO.Path.GetInvalidFileNameChars();
            var cleaned = new string(serviceId.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray());
            return string.IsNullOrWhiteSpace(cleaned) ? "default" : cleaned;
        }

        ~RedisHistoryStorage()
        {
            Dispose(false);
        }

        private async Task PublishMirrorRequestAsync(HistoryStoreRequest request)
        {
            if (_rabbitRepo == null) return;

            try
            {
                await _rabbitRepo.PublishAsync("historyStore", request);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed publishing history mirror request for {Operation} session {SessionId}",
                    request.Operation, request.SessionId);
            }
        }
    }
}

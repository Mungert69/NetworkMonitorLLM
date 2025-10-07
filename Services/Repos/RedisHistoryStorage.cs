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

namespace NetworkMonitor.LLM.Services
{
    public class RedisHistoryStorage : IHistoryStorage, IDisposable
    {
        private readonly ConnectionMultiplexer _redis;
        private readonly IDatabase _db;
        private readonly string _keyPrefix = "history:";
        private const  string IndexKey   = "idx:history:all"; 
        private bool _disposed = false;
        private readonly ILogger _logger;

        public RedisHistoryStorage(ILogger<RedisHistoryStorage> logger, SystemParams systemParams)
        {
            var configuration = BuildConfiguration(systemParams.RedisUrl, systemParams.RedisSecret);
            _logger = logger;
            _redis = ConnectionMultiplexer.Connect(configuration);
            _db = _redis.GetDatabase();
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
            if (await _db.SetLengthAsync(IndexKey) > 0) return;

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
                await _db.SetAddAsync(IndexKey, indexValues.ToArray());
            }
        }

        public async Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
        {
            var sessions = new ConcurrentDictionary<string, Session>();

            //await EnsureIndexSetAsync(); /// remove this after first run 

            // 1) Grab your pre‐maintained index of history‐keys:
            var rawKeys = await _db.SetMembersAsync(IndexKey);
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

        public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId)
        {
            var historyDisplayNames = new List<HistoryDisplayName>();
            var server = GetServer();
            var keys = await GetKeysAsync(server, $"{_keyPrefix}*_{userId}_*");

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
            _ = tran.SetAddAsync(IndexKey, key);

            await tran.ExecuteAsync().ConfigureAwait(false);
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
                    _ = tran.SetRemoveAsync(IndexKey, (RedisValue)keyString);
                }
            }
            await tran.ExecuteAsync().ConfigureAwait(false);
        }


        private async Task<HistoryDisplayName?> LoadFromKey(RedisKey key)
        {
            var json = await _db.StringGetAsync(key);
            return json.HasValue
                ? JsonConvert.DeserializeObject<HistoryDisplayName>(json.ToString())
                : null;
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

        ~RedisHistoryStorage()
        {
            Dispose(false);
        }
    }
}

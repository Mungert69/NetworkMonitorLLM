using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using StackExchange.Redis;
using NetworkMonitor.Utils.Helpers;

namespace NetworkMonitor.LLM.Services
{
    public class RedisHistoryStorage : IHistoryStorage, IDisposable
    {
        private readonly ConnectionMultiplexer _redis;
        private readonly IDatabase _db;
        private readonly string _keyPrefix = "history:";
        private bool _disposed = false;

        public RedisHistoryStorage(ISystemParamsHelper systemParamsHelper)
        {
            var systemParams = systemParamsHelper.GetSystemParams();
            var configuration = BuildConfiguration(systemParams.RedisUrl, systemParams.RedisSecret);

            _redis = ConnectionMultiplexer.Connect(configuration);
            _db = _redis.GetDatabase();
        }

        private ConfigurationOptions BuildConfiguration(string redisUrl, string redisSecret)
        {
            var config = new ConfigurationOptions
            {
                // Basic connection
                EndPoints = { redisUrl },  // e.g. "your-server:46379"
                Password = redisSecret,

                // TLS Configuration
                Ssl = true,
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12,

                // Connection tuning
                ConnectTimeout = 5000,
                SyncTimeout = 5000,
                AbortOnConnectFail = false
            };


            config.CertificateValidation += (sender, cert, chain, errors) => true;


            return config;
        }
        public async Task<ConcurrentDictionary<string, Session>> LoadAllSessionsAsync()
        {
            var sessions = new ConcurrentDictionary<string, Session>();
            var server = GetServer();

            try
            {
                await foreach (var key in ScanKeysAsync(server, $"{_keyPrefix}*"))
                {
                    try
                    {
                        var history = await LoadFromKey(key);
                        if (history != null)
                        {
                            sessions.TryAdd(history.SessionId, new Session
                            {
                                HistoryDisplayName = history,
                                Runner = null
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error loading session from Redis key {key}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning Redis keys: {ex.Message}");
            }

            return sessions;
        }

        public async Task<List<HistoryDisplayName>> GetHistoryDisplayNamesAsync(string userId)
        {
            var historyDisplayNames = new List<HistoryDisplayName>();
            var server = GetServer();

            await foreach (var key in ScanKeysAsync(server, $"{_keyPrefix}*_{userId}_*"))
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

        public async Task SaveHistoryAsync(HistoryDisplayName historyDisplayName)
        {
            if (historyDisplayName == null)
                throw new ArgumentNullException(nameof(historyDisplayName));

            var key = $"{_keyPrefix}{historyDisplayName.StartUnixTime}_{historyDisplayName.SessionId}";
            var json = JsonConvert.SerializeObject(historyDisplayName, new JsonSerializerSettings
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver(),
                Formatting = Formatting.Indented
            });

            await _db.StringSetAsync(key, json);
        }

        public async Task<HistoryDisplayName?> LoadHistoryAsync(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                throw new ArgumentException("Session ID cannot be empty", nameof(sessionId));

            var server = GetServer();

            await foreach (var key in ScanKeysAsync(server, $"{_keyPrefix}*_{sessionId}"))
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

        public async Task DeleteHistoryAsync(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                throw new ArgumentException("Session ID cannot be empty", nameof(sessionId));

            var server = GetServer();

            await foreach (var key in ScanKeysAsync(server, $"{_keyPrefix}*_{sessionId}"))
            {
                await _db.KeyDeleteAsync(key);
            }
        }

        private async Task<HistoryDisplayName?> LoadFromKey(RedisKey key)
        {
            var json = await _db.StringGetAsync(key);
            return json.HasValue
                ? JsonConvert.DeserializeObject<HistoryDisplayName>(json)
                : null;
        }

        private IServer GetServer()
        {
            var endpoints = _redis.GetEndPoints();
            if (endpoints.Length == 0)
                throw new InvalidOperationException("No Redis endpoints available");

            return _redis.GetServer(endpoints.First());
        }

        private async IAsyncEnumerable<RedisKey> ScanKeysAsync(IServer server, string pattern)
        {
            var cursor = 0;
            do
            {
                var scanResult = await server.KeysAsync(
                    database: _db.Database,
                    pattern: pattern,
                    pageSize: 100,
                    cursor: cursor);

                foreach (var key in scanResult)
                {
                    yield return key;
                }

                cursor = scanResult.Cursor;
            } while (cursor != 0);
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
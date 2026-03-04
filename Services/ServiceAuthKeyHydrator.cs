using System;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects;
using NetworkMonitor.Utils;

namespace NetworkMonitor.LLM.Services;

public static class ServiceAuthKeyHydrator
{
    public static string Resolve(SystemParams systemParams, ILogger logger, string context)
    {
        var configured = systemParams.ServiceAuthKey;
        if (!string.IsNullOrWhiteSpace(configured) &&
            !string.Equals(configured, "Missing", StringComparison.Ordinal))
        {
            return configured;
        }

        if (!string.IsNullOrWhiteSpace(systemParams.LLMEncryptKey) &&
            !string.Equals(systemParams.LLMEncryptKey, "Missing", StringComparison.Ordinal))
        {
            var fallback = AesOperation.EncryptString(systemParams.LLMEncryptKey, systemParams.ServiceID ?? "Service");
            logger.LogWarning(
                "ServiceAuthKey is empty for service '{ServiceId}'. Generated fallback from LLMEncryptKey in {Context}.",
                systemParams.ServiceID,
                context);
            systemParams.ServiceAuthKey = fallback;
            return fallback;
        }

        logger.LogError(
            "ServiceAuthKey and LLMEncryptKey are both missing for service '{ServiceId}' in {Context}. Auth-validated messaging will fail.",
            systemParams.ServiceID,
            context);
        systemParams.ServiceAuthKey = "Missing";
        return systemParams.ServiceAuthKey;
    }
}

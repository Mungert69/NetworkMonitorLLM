---
title: Local Model Runtime
kind: component
updated: 2026-08-06
sources: [Services/Factory/LLMProcessorRunner.cs, Services/Factory/LLMRunnerFactory.cs, scripts]
---

# Local Model Runtime

## Summary

`TestLLM` is the local-process runner path. It is created by the process-runner
factory and keeps host-owned persistent context distinct from portable API
history.

## Details

The local runner uses an `LLMConfig` selected by model version to construct its
prompt and a matching token broadcaster to parse output. It is serialized by a
dedicated process-runner semaphore in the factory. The scripts directory also
contains local llama-server run/control scripts; the controller supports start,
stop, restart, status, and logs with configurable host, port, PID, and log
paths.

## Relationships

- [components/history-storage](https://github.com/Mungert69/NetworkMonitorLLM/wiki/history-storage) explains local-context durability.
- [concepts/model-format-adapters](https://github.com/Mungert69/NetworkMonitorLLM/wiki/model-format-adapters) describes its prompt/parser pairing.
- [concepts/deployment-assets](https://github.com/Mungert69/NetworkMonitorLLM/wiki/deployment-assets) covers the build/run assets.

## Sources

- `../../../Services/Factory/LLMProcessorRunner.cs`
- `../../../Services/Factory/LLMRunnerFactory.cs`
- `../../../scripts/llama-server-control.sh`

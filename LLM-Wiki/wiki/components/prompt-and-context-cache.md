---
title: Prompt Rendering and Context Cache
kind: component
updated: 2026-08-06
sources: [Services/Prompts, Services/Cache]
---

# Prompt Rendering and Context Cache

## Summary

Prompt rendering produces the static context needed by local model operation;
the remote cache subsystem can restore or share expensive generated context
files across container restarts.

## Details

The prompt layer contains `PromptRenderer` and `SystemPromptWriter`. The cache
layer defines a common remote-cache interface, HTTP and S3-compatible
implementations, and a factory. Its documentation describes a SHA-256-derived
context filename based on stable prompt content: on a local miss, the system
may restore remotely; on a remote miss, it builds locally then uploads.

Per-session data is intentionally excluded from the static cache key and is
injected at runtime. Conversation history and local recovery state remain the
responsibility of the history stores.

## Relationships

- [components/local-model-runtime](https://github.com/Mungert69/NetworkMonitorLLM/wiki/local-model-runtime) uses model prompt contexts.
- [components/history-storage](https://github.com/Mungert69/NetworkMonitorLLM/wiki/history-storage) owns material deliberately excluded from cache.

## Sources

- `../../../Services/Prompts/PromptRenderer.cs`
- `../../../Services/Prompts/SystemPromptWriter.cs`
- `../../../Services/Cache/README.md`

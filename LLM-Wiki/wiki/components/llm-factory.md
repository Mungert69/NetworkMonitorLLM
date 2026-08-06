---
title: LLM Factory
kind: component
updated: 2026-08-06
sources: [Services/Factory/LLMFactory.cs]
---

# LLM Factory

## Summary

`LLMFactory` creates runners and coordinates session history ownership. It
holds the live session collection and uses separate concurrency controls for
local process, OpenAI, and Hugging Face runner work.

## Details

The factory is constructed with shared history storage, a local session store,
a response processor, resource monitor, query coordinator, and service
identity. At startup it loads shared sessions except local-context runner
sessions, then overlays sessions from the local store. This prevents a legacy
shared record from replacing the host-owned local context.

When saving or deleting history, runner type determines the store: local
persistent-context runners use `ILocalLlmSessionStore`; other runners use
`IHistoryStorage`.

## Relationships

- [concepts/runner-routing](https://github.com/Mungert69/NetworkMonitorLLM/wiki/runner-routing) describes the runners it selects.
- [components/history-storage](https://github.com/Mungert69/NetworkMonitorLLM/wiki/history-storage) describes the two persistence boundaries.

## Sources

- [sources/repository-overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-overview)
- `../../../Services/Factory/LLMFactory.cs`

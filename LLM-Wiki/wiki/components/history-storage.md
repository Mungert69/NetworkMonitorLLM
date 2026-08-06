---
title: Conversation History Storage
kind: component
updated: 2026-08-06
sources: [Services/Repos/README.md, Services/Factory/LLMFactory.cs]
---

# Conversation History Storage

## Summary

Conversation persistence deliberately distinguishes portable, shared API-runner
histories from host-owned local LLM context.

## Details

`IHistoryStorage` is the shared Redis-backed store used by `TurboLLM` and
`HugLLM`; their portable chat messages can be resumed on another service.
`ILocalLlmSessionStore` is used for `TestLLM` and writes one JSON record per
session to a configurable local path. The record includes both replay history
and the exact local process context.

Local sessions must be resumed or deleted on the originating local LLM server.
The local store writes a temporary JSON file and atomically replaces the prior
record to avoid partial writes.

## Relationships

- [components/llm-factory](https://github.com/Mungert69/NetworkMonitorLLM/wiki/llm-factory) enforces this storage choice.
- [concepts/runner-routing](https://github.com/Mungert69/NetworkMonitorLLM/wiki/runner-routing) names the affected runner types.

## Sources

- [sources/repository-overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-overview)
- `../../../Services/Repos/README.md`
- `../../../Services/Factory/LLMFactory.cs`

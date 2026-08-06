---
title: NetworkMonitorLLM Overview
kind: overview
updated: 2026-08-06
sources: [README.md, Program.cs]
---

# NetworkMonitorLLM Overview

## Summary

NetworkMonitorLLM is a .NET service that orchestrates LLM-backed network
monitoring, security, and automation conversations. It accepts work through
the wider Network Monitor message flow, manages an isolated session, chooses a
runner, obtains model output and tool calls, then returns processed results.

## Details

The service supports API-backed OpenAI and Hugging Face-compatible models as
well as local `llama.cpp` processes. Expert-specific tool builders provide the
system prompt and callable functions. Session histories are persisted either in
a shared history store or a local persistent context store, depending on the
runner type.

`Program.cs` builds an ASP.NET host from `appsettings.json`. It uses a fixed
configured port when enabled; otherwise it derives a service port from the
service identifier.

## Relationships

- [architecture](https://github.com/Mungert69/NetworkMonitorLLM/wiki/architecture) describes the end-to-end flow.
- [concepts/runner-routing](https://github.com/Mungert69/NetworkMonitorLLM/wiki/runner-routing) explains provider and runner selection.
- [components/history-storage](https://github.com/Mungert69/NetworkMonitorLLM/wiki/history-storage) explains persistence boundaries.

## Sources

- [sources/repository-overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-overview)
- `../../README.md`
- `../../Program.cs`

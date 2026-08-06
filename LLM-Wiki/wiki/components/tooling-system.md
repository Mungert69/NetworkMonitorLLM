---
title: Tooling System
kind: component
updated: 2026-08-06
sources: [Services/ToolsBuilders]
---

# Tooling System

## Summary

The tooling system turns the service role and runner configuration into a
system prompt plus a typed catalog of callable functions.

## Details

`ToolsBuilderFactory` selects monitor prompt variants and dedicated builders
for expert domains. The directory groups these builders under agents, experts,
and general monitor/report/blog builders; `Tools/` contains the function
definitions they expose. The primary monitor role may be selected per runner
and includes standard, simple, and HAL9000-oriented variants.

`FunctionDefinitionRegistry` discovers function definitions and can publish a
complete or filtered JSON catalog. The filtered catalog omits function IDs that
end in `_expert`.

## Relationships

- [components/messaging-and-session-service](https://github.com/Mungert69/NetworkMonitorLLM/wiki/messaging-and-session-service) responds to function-catalog requests.
- [concepts/tool-calling](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tool-calling) consumes the resulting definitions at model runtime.

## Sources

- `../../../Services/ToolsBuilders/ToolsBuilderFactory.cs`
- `../../../Services/ToolsBuilders/FunctionDefinitionRegistry.cs`
- `../../../Services/ToolsBuilders/`

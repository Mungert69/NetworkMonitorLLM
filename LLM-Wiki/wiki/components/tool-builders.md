---
title: Tool Builders
kind: component
updated: 2026-08-06
sources: [Services/ToolsBuilders/ToolsBuilderBase.cs]
---

# Tool Builders

## Summary

Tool builders define the expert-specific system prompt and the list of callable
tools available to a model session.

## Details

`IToolsBuilder` exposes prompt construction for a normal or resumed session,
the tool definitions, and a display-friendly list of function names.
`ToolsBuilderBase` parses tool definitions from JSON and supplies a default
resume prompt containing the current time. Concrete builders provide the
domain-specific system prompts.

## Relationships

- [concepts/tool-calling](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tool-calling) explains how model-issued calls are parsed.
- [architecture](https://github.com/Mungert69/NetworkMonitorLLM/wiki/architecture) places tool calls in the request flow.

## Sources

- [sources/repository-overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-overview)
- `../../../Services/ToolsBuilders/ToolsBuilderBase.cs`

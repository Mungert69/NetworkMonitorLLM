---
title: Tool Calling Formats
kind: concept
updated: 2026-08-06
sources: [README.md]
---

# Tool Calling Formats

## Summary

The service supports XML and JSON model output formats for function calls,
selected by `MLParams.XmlFunctionParsing`.

## Details

In XML mode, models emit `function_call` blocks containing parameters; the
base token broadcaster extracts them and serializes parameters to JSON. In JSON
mode, model-specific token broadcasters extract the function name and
arguments, including sanitation or repair when necessary. OpenAI response
handling applies XML parsing when enabled; Hugging Face handling prefers
structured tool calls and otherwise uses the configured XML or JSON fallback.

## Relationships

- [components/tool-builders](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tool-builders) defines the tools exposed to the model.
- [architecture](https://github.com/Mungert69/NetworkMonitorLLM/wiki/architecture) shows where response parsing occurs.

## Sources

- [sources/repository-overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-overview)
- `../../../README.md`

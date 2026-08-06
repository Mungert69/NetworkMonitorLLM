---
title: Model Format Adapters
kind: concept
updated: 2026-08-06
sources: [Services/TokenBroadcasters]
---

# Model Format Adapters

## Summary

The service separates model-specific prompt wire formats and streamed-output
parsing from runner lifecycle management.

## Details

`LLMConfigFactory` selects an `LLMConfig` from an LLM version. A configuration
defines message templates, end tokens, function-call representation, prompt
footers, and the token broadcaster factory. The token-broadcaster directory
contains implementations for Functionary, Llama, Qwen, Gemma, Phi, DeepSeek,
MiniCPM, GLM, GPT-OSS, and other model families, with focused tests for many
formats.

This arrangement means a runner can construct and parse a protocol compatible
with the selected model while the shared service flow remains unchanged.

## Relationships

- [components/local-model-runtime](https://github.com/Mungert69/NetworkMonitorLLM/wiki/local-model-runtime) creates the configured broadcaster locally.
- [concepts/tool-calling](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tool-calling) describes the common function-call objective.

## Sources

- `../../../Services/TokenBroadcasters/LLMConfigFactory.cs`
- `../../../Services/TokenBroadcasters/`

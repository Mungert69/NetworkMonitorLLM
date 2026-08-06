---
title: Runner and Provider Routing
kind: concept
updated: 2026-08-06
sources: [README.md]
---

# Runner and Provider Routing

## Summary

The configured runner type selects the execution path, while provider settings
select the compatible API behavior for API-backed runners.

## Details

The repository documentation defines `TurboLLM` as an OpenAI-schema path and
`HugLLM` as a Hugging Face/OpenRouter JSON-schema path. `LlmProvider` can name
OpenAI, Hugging Face, or their Rabbit variants; HugLLM forces the Hugging Face
provider path. Local runners are managed as processes and preserve host-local
context separately from portable histories.

## Relationships

- [components/llm-factory](https://github.com/Mungert69/NetworkMonitorLLM/wiki/llm-factory) owns runner creation and session behavior.
- [components/history-storage](https://github.com/Mungert69/NetworkMonitorLLM/wiki/history-storage) explains persistence implications.

## Sources

- [sources/repository-overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-overview)
- `../../../README.md`

---
title: API Adapters
kind: component
updated: 2026-08-06
sources: [Services/Api/LLMApiFactory.cs, Services/Api]
---

# API Adapters

## Summary

The API layer presents one `ILLMApi` contract while selecting provider-specific
completion and transport implementations.

## Details

`LLMApiFactory` maps OpenAI and Hugging Face providers to HTTP-backed adapters.
It maps `OpenAIRabbit` and `HuggingFaceRabbit` to RabbitMQ transport adapters,
constructed with the response processor's Rabbit repository and configured
system URL/routing key. An unknown provider is rejected with an argument error.

The surrounding API directory contains request/response conversion, chat
message logging, OpenAI wire-format handling, Hugging Face processing,
normalization, and worker support such as audio generation, hedge policy, and
worker metrics.

## Relationships

- [concepts/runner-routing](https://github.com/Mungert69/NetworkMonitorLLM/wiki/runner-routing) chooses the provider path.
- [components/application-host](https://github.com/Mungert69/NetworkMonitorLLM/wiki/application-host) configures the HTTP client used by OpenAI.
- [components/tooling-system](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tooling-system) supplies definitions used to build model prompts.

## Sources

- `../../../Services/Api/LLMApiFactory.cs`
- `../../../Services/Api/`

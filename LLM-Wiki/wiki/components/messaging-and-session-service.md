---
title: Messaging and Session Service
kind: component
updated: 2026-08-06
sources: [Services/RabbitListener.cs, Services/LLMService.cs]
---

# Messaging and Session Service

## Summary

RabbitMQ is the external control plane. `RabbitListener` declares consumers for
session start, user input, stop/remove, query-index results, and function
registry requests; `LLMService` owns the corresponding live session lifecycle.

## Details

The listener derives exchange names by combining each operation with the
configured service ID and dispatches messages asynchronously. `LLMService`
loads prior sessions during initialization. A session key combines the request
session ID and requested runner type, and a per-session semaphore prevents
concurrent start races.

On a new or failed runner, the service creates and starts a runner through
`LLMFactory`; enabled runners are recorded in the session collection. Removing
a session saves its history before runner process removal. The service uses a
readiness wait during startup and reports user-facing status through RabbitMQ.

## Relationships

- [components/llm-factory](https://github.com/Mungert69/NetworkMonitorLLM/wiki/llm-factory) creates the selected runner.
- [components/history-storage](https://github.com/Mungert69/NetworkMonitorLLM/wiki/history-storage) persists history during removal and normal use.
- [components/tooling-system](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tooling-system) publishes the callable function catalog.

## Sources

- `../../../Services/RabbitListener.cs`
- `../../../Services/LLMService.cs`

---
title: NetworkMonitorLLM Wiki Index
kind: index
updated: 2026-08-06
---

# NetworkMonitorLLM Wiki Index

Start here when exploring the knowledge base. The service is a modular LLM
orchestration component for network-monitoring workflows.

## Overviews

- [overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/overview) — purpose, boundaries, and main request flow.
- [architecture](https://github.com/Mungert69/NetworkMonitorLLM/wiki/architecture) — components and the request lifecycle.
- [sources/repository-corpus](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-corpus) — complete source boundary and repository map.

## Components

- [components/llm-factory](https://github.com/Mungert69/NetworkMonitorLLM/wiki/llm-factory) — runner creation, session ownership, and history routing.
- [components/tool-builders](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tool-builders) — expert prompts and tool definitions.
- [components/history-storage](https://github.com/Mungert69/NetworkMonitorLLM/wiki/history-storage) — shared and local persistence models.
- [components/application-host](https://github.com/Mungert69/NetworkMonitorLLM/wiki/application-host) — host startup, dependency injection, and health endpoint.
- [components/messaging-and-session-service](https://github.com/Mungert69/NetworkMonitorLLM/wiki/messaging-and-session-service) — RabbitMQ entry points and session lifecycle.
- [components/api-adapters](https://github.com/Mungert69/NetworkMonitorLLM/wiki/api-adapters) — provider-specific completion adapters and transport choices.
- [components/local-model-runtime](https://github.com/Mungert69/NetworkMonitorLLM/wiki/local-model-runtime) — local `llama.cpp` process execution and prompt contexts.
- [components/tooling-system](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tooling-system) — tool-builder selection and function registry.
- [components/prompt-and-context-cache](https://github.com/Mungert69/NetworkMonitorLLM/wiki/prompt-and-context-cache) — prompt rendering and remote context caching.

## Concepts

- [concepts/runner-routing](https://github.com/Mungert69/NetworkMonitorLLM/wiki/runner-routing) — local, OpenAI, and Hugging Face runner selection.
- [concepts/tool-calling](https://github.com/Mungert69/NetworkMonitorLLM/wiki/tool-calling) — XML and JSON function-call processing.
- [concepts/model-format-adapters](https://github.com/Mungert69/NetworkMonitorLLM/wiki/model-format-adapters) — model-specific token broadcasters and prompt formats.
- [concepts/deployment-assets](https://github.com/Mungert69/NetworkMonitorLLM/wiki/deployment-assets) — model build/run scripts, containers, and systemd units.

## Sources

- [sources/repository-overview](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-overview) — initial focused implementation review.
- [sources/repository-corpus](https://github.com/Mungert69/NetworkMonitorLLM/wiki/repository-corpus) — repository-wide corpus inventory.

## Operations

- [log](https://github.com/Mungert69/NetworkMonitorLLM/wiki/log) — chronological maintenance history.

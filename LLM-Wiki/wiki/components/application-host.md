---
title: Application Host and Composition Root
kind: component
updated: 2026-08-06
sources: [Program.cs, Startup.cs, NetworkMonitorLLM.csproj]
---

# Application Host and Composition Root

## Summary

The application is a .NET 10 executable hosted by ASP.NET Core. `Program` reads
`appsettings.json`, creates the web host, and selects either a configured port
or a port derived from the service identifier.

## Details

`Startup.ConfigureServices` is the composition root. It registers messaging,
LLM service/factory, history stores, resource monitoring, query coordination,
tool builders, prompt writing, audio generation, and remote cache services.
It also creates an OpenAI client with an optional configured base domain and a
handler chain that rewrites Novita paths and logs requests.

Asynchronous startup connects the Rabbit repository, sets up the listener, and
initializes the LLM service. When a fixed port is enabled, the HTTP surface
exposes `GET /health`, returning a small healthy JSON response.

## Relationships

- [components/messaging-and-session-service](https://github.com/Mungert69/NetworkMonitorLLM/wiki/messaging-and-session-service) starts after DI composition.
- [components/api-adapters](https://github.com/Mungert69/NetworkMonitorLLM/wiki/api-adapters) uses the registered OpenAI service.
- [components/prompt-and-context-cache](https://github.com/Mungert69/NetworkMonitorLLM/wiki/prompt-and-context-cache) is registered from this host.

## Sources

- `../../../Program.cs`
- `../../../Startup.cs`
- `../../../NetworkMonitorLLM.csproj`

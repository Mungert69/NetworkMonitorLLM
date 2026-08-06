---
title: Deployment and Model Assets
kind: concept
updated: 2026-08-06
sources: [docker-build, service-files, func, llama, root scripts]
---

# Deployment and Model Assets

## Summary

The repository includes operational assets alongside the service code: local
model build/run scripts, prompt templates, container definitions, patches, and
systemd service units for the different expert roles.

## Details

`func/` and `llama/` organize model-family-specific build and run assets.
Root-level `build-*`, `run-*`, and `system_prompt_*` files supply additional
model variants. `docker-build/` contains images for development and CPU/no-local
llama cases; the main Dockerfile describes an Ubuntu/CUDA-oriented environment
that builds llama.cpp and downloads a Phi model. `service-files/` contains units
for monitor, security/nmap, search, memory, camera, agent-flow, and related
roles, plus a local llama-server unit.

Some operational files can contain environment- or deployment-specific values;
wiki maintenance should cite them without treating embedded values as portable
defaults.

## Relationships

- [components/local-model-runtime](https://github.com/Mungert69/NetworkMonitorLLM/wiki/local-model-runtime) is operated by the local model assets.
- [concepts/runner-routing](https://github.com/Mungert69/NetworkMonitorLLM/wiki/runner-routing) explains runtime selection after deployment.

## Sources

- `../../../docker-build/`
- `../../../service-files/`
- `../../../func/`
- `../../../llama/`
- `../../../scripts/`

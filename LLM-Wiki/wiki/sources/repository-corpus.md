---
title: Repository Source Corpus
kind: source
updated: 2026-08-06
sources: [repository-root]
---

# Repository Source Corpus

## Summary

The NetworkMonitorLLM repository itself is the source for this wiki. The wiki
does not ingest a copy of the codebase: it reads the files in place and writes
only derived Markdown under `LLM-Wiki/wiki/`.

## Included and excluded paths

Included: all authored files under the repository root—C# application and test
code, project files, documentation, prompt templates, model build/run scripts,
Docker files, patch files, and service-unit definitions.

Excluded: `LLM-Wiki/` (the derived knowledge base), `.git/` (version-control
internals), `bin/`, and `obj/` (build output). `raw/` is only for optional
supplementary source documents.

## Corpus map

The initial inventory contains 393 authored files under this boundary.

- `Services/Api/` — provider APIs, conversion, response processing helpers,
  workers, and tests.
- `Services/Factory/`, `Services/Repos/`, and root `Services/` — orchestration,
  runners, persistence, message handling, host support, and tests.
- `Services/ToolsBuilders/` — domain tool definitions, prompts, builders, and
  function registry.
- `Services/TokenBroadcasters/` — model-specific streamed-output parsers and
  prompt-format configuration.
- `func/` and `llama/` — functionary and Llama model build/run assets.
- root-level `build-*`, `run-*`, and `system_prompt_*` files — additional model
  build and prompt assets.
- `docker-build/` and `service-files/` — container and operational deployment
  assets.

Run `LLM-Wiki/scripts/repository-source-list.sh` for the current exact list.

## Sources

- Repository root excluding the paths listed above

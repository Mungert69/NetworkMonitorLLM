# LLM Wiki operating schema

## Canonical wiki and publishing boundary

- `LLM-Wiki/wiki/` is the canonical, editable wiki. Make content changes here
  and commit them with the main repository.
- The GitHub Wiki is a published frontend backed by the separate
  `NetworkMonitorLLM.wiki.git` repository. Publish a copy from the local wiki;
  do not use browser edits as a parallel source of truth.
- Reconcile any deliberate GitHub-side edit into `LLM-Wiki/wiki/` before the
  next publication.

## Source boundary

- The source corpus is the `NetworkMonitorLLM` repository root, excluding
  `LLM-Wiki/`, `.git/`, `bin/`, and `obj/`. It includes source code,
  documentation, prompts, scripts, Docker files, service units, configuration
  examples, and tests.
- Treat every corpus file and optional `raw/` file as immutable while
  maintaining the wiki. Never edit, rename, or delete a source as part of
  wiki work.
- The `wiki/` directory is agent-owned. Make all derived summaries, analyses,
  cross-references, and indexes there.
- Keep factual claims attributable: each substantive page must name its source
  pages or source files under `## Sources`.
- Do not treat generated wiki claims as stronger evidence than their sources.
  Preserve uncertainty and explicitly record contradictions or open questions.

## Page format

New durable pages use this structure:

```markdown
---
title: Human-readable title
kind: overview | concept | component | source | analysis
updated: YYYY-MM-DD
sources: [relative/source/path]
---

# Title

## Summary

## Details

## Relationships

## Sources
```

## GitHub Wiki publishing format

These pages are published from the local canonical wiki to the GitHub Wiki at
`https://github.com/Mungert69/NetworkMonitorLLM/wiki`. GitHub Wiki serves a
page by its filename, not its source directory. Write every internal link as a
standard Markdown hyperlink using the complete Wiki URL and the filename
without `.md`, for example:

```markdown
[Request architecture](https://github.com/Mungert69/NetworkMonitorLLM/wiki/architecture)
[LLM factory](https://github.com/Mungert69/NetworkMonitorLLM/wiki/llm-factory)
```

Never use Obsidian `[[wiki links]]`: they are not the supported Markdown link
format for this GitHub Wiki. A local page may live in `components/` or
`concepts/` for organization, but its public link must not include that folder.
Use unique lowercase, hyphenated filenames. Add a source page before citing a
newly ingested source.

## Ingest workflow

1. Read `wiki/index.md` and the relevant repository source files first.
2. Create or update a source-map page when the change introduces a new source
   area; otherwise cite the exact repository paths on affected pages.
3. Update the relevant overview, component, and concept pages. Prefer a
   focused update to a large page rewrite.
4. Add missing pages when a recurring entity or concept deserves one.
5. Update `wiki/index.md`, then append one dated entry to `wiki/log.md`.
6. Flag disagreements under `## Open questions and contradictions`; do not
   silently overwrite older claims.

## Query workflow

1. Search `wiki/index.md` and relevant pages (use `scripts/wiki-search.sh` at
   larger scale).
2. Answer only from the pages and their cited sources; state material gaps.
3. If the answer is reusable, file it under `wiki/analysis/`, link it from the
   index, and append a `query` entry to the log.

## Lint workflow

Periodically run `scripts/wiki-lint.sh`, repair broken links and stale index
entries, identify orphan pages, and append a `lint` entry to `wiki/log.md`.

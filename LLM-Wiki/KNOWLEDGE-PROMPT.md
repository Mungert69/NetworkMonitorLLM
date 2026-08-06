# LLM Wiki: Local Source of Truth with GitHub Wiki Frontend

Use this prompt to configure an LLM agent as the maintainer of this project's
knowledge base.

## Purpose

Build and maintain a persistent, interlinked Markdown wiki for the project.
The wiki is not a one-time RAG index: every source ingestion and useful
investigation improves a durable knowledge artifact. The agent owns the
bookkeeping—summaries, cross-references, source attribution, contradictions,
indexing, and maintenance—while humans curate sources and direct the work.

## The three layers

### 1. Repository source corpus

The authoritative subject matter is the local `NetworkMonitorLLM` repository,
excluding `LLM-Wiki/`, `.git/`, `bin/`, and `obj/`. Read source code,
documentation, tests, prompt assets, scripts, Docker files, and service units
in place. They are immutable while performing wiki maintenance.

`LLM-Wiki/raw/` is only for supplementary user-provided documents that do not
belong in the repository. Once added, treat each raw document as immutable.

### 2. Canonical local wiki

`LLM-Wiki/wiki/` is the canonical, editable knowledge base. All LLM-generated
summaries, analyses, indexes, source maps, and log entries are written here.
This directory is the source of truth for wiki content and must be committed
with the main repository when its changes are ready.

Read `LLM-Wiki/wiki/index.md` before answering a wiki question or ingesting
repository changes. Maintain `LLM-Wiki/wiki/log.md` as an append-only record.

### 3. GitHub Wiki frontend

`https://github.com/Mungert69/NetworkMonitorLLM/wiki` is the published,
read-only frontend for the canonical local wiki. It is backed by the separate
Git repository `NetworkMonitorLLM.wiki.git`; it is not the main repository and
it is not a second source of truth.

Do not maintain content by editing GitHub Wiki pages in the browser. Make every
content change locally under `LLM-Wiki/wiki/`, validate it, commit it to the
main repository, then publish a copy to the GitHub Wiki repository. If someone
has edited GitHub Wiki directly, reconcile that change into the local canonical
wiki before the next publish.

## GitHub Wiki page and link rules

GitHub Wiki serves a page by its filename, even when the source Markdown file
is stored in a local subdirectory. Therefore, local folders may organize pages,
but all page filenames must be globally unique and public links must use only
the filename without `.md`.

For example:

```text
Local file: LLM-Wiki/wiki/components/llm-factory.md
Live page:  https://github.com/Mungert69/NetworkMonitorLLM/wiki/llm-factory
```

Use standard Markdown links in every generated page:

```markdown
[LLM Factory](https://github.com/Mungert69/NetworkMonitorLLM/wiki/llm-factory)
```

Never use Obsidian `[[wiki links]]`, relative links, or a local directory in a
GitHub Wiki URL. `index.md` is the local index; when publishing, copy it to
`Home.md` so it becomes the GitHub Wiki landing page.

## Page convention

Use lowercase, hyphenated, globally unique filenames. Durable pages have this
shape:

```markdown
---
title: Human-readable title
kind: overview | concept | component | source | analysis
updated: YYYY-MM-DD
sources: [repository/path]
---

# Title

## Summary

## Details

## Relationships

## Sources
```

Every substantive claim must be traceable under `## Sources`. Do not promote a
generated claim over the source evidence. Preserve uncertainty, open questions,
and contradictions instead of silently rewriting history.

## Ingest repository changes

1. Identify the changed repository files, excluding the wiki and generated
   output directories.
2. Read `index.md`, related pages, and the relevant sources.
3. Create or update the appropriate source map, overview, component, and
   concept pages.
4. Add a page only when the topic is durable and has a globally unique name.
5. Update `index.md` with a GitHub-compatible Markdown link.
6. Append one dated `ingest` entry to `log.md`, including the changed source
   areas and important additions, corrections, or uncertainties.
7. Run `LLM-Wiki/scripts/wiki-lint.sh` before publishing.

## Answer questions

1. Search `index.md` and relevant pages; use
   `LLM-Wiki/scripts/wiki-search.sh <terms>` when useful.
2. Answer from the canonical local wiki and its cited source files.
3. State meaningful evidence gaps.
4. If the result is reusable, save it as an `analysis` page, add it to the
   index, and append a dated `query` entry to the log.

## Health checks

Periodically lint the wiki and investigate:

- broken or ambiguous GitHub Wiki links;
- pages missing from the index;
- orphan pages and missing cross-references;
- contradictions, superseded claims, and missing source attribution;
- concepts that recur but lack a durable page; and
- valuable questions or data gaps for future research.

Record a dated `lint` entry after a meaningful maintenance pass.

## Publish to GitHub Wiki

After the local wiki passes lint, publish `LLM-Wiki/wiki/` to the separate
`NetworkMonitorLLM.wiki.git` checkout. Copy `index.md` to `Home.md` in that
checkout, then commit and push its default branch. Keep the local page
directories for organization, but do not put directory names in page URLs.

The normal sequence is:

```text
repository sources → LLM-Wiki/wiki (canonical) → GitHub Wiki (published view)
```

Never reverse that direction without explicitly reconciling a deliberate
GitHub-side edit back into the local canonical wiki.

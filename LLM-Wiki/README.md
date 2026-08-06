# NetworkMonitorLLM Wiki

This is the maintained knowledge base for the NetworkMonitorLLM service. It is
an Obsidian-compatible Markdown vault that records the *explained* system. Its
source corpus is this repository, excluding this `LLM-Wiki/` directory (and
non-authored VCS/build output directories).

## Layout

- `raw/` — optional immutable, user-supplied supplementary sources.
- `wiki/` — generated and maintained knowledge pages.
- `wiki/index.md` — the content catalog and starting point for questions.
- `wiki/log.md` — append-only record of ingests, queries, and maintenance.
- `AGENTS.md` — operating rules for an LLM working in this vault.
- `KNOWLEDGE-PROMPT.md` — portable high-level prompt for this local-canonical,
  GitHub-published wiki pattern.
- `scripts/` — small local search and health-check helpers.

## Working with it

1. Put a new document in `raw/` (or tell the agent which repository files are
   the source).
2. Ask: “Ingest `raw/<file>` into the LLM Wiki.”
3. Review the source summary and the linked pages the agent changed.
4. Ask questions against the wiki. Useful findings should be saved as analysis
   pages and linked from the index.

See [the repository corpus map](wiki/sources/repository-corpus.md) for the
authoritative source boundary and a directory-level map. Repository files are
read in place—application code is not copied, moved, or modified to build the
wiki.

Run `scripts/wiki-search.sh <terms>` to search the generated pages,
`scripts/repository-source-list.sh` to list the source corpus, and
`scripts/wiki-lint.sh` to check basic link and index hygiene.

`LLM-Wiki/wiki/` is canonical. The GitHub Wiki is a published frontend; update
the local pages first and publish them only after validation.

#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
wiki="$root/wiki"
index="$wiki/index.md"
wiki_base_url="https://github.com/Mungert69/NetworkMonitorLLM/wiki"
status=0

if rg --quiet '\[\[[^]]+\]\]' "$wiki"; then
  echo "Obsidian-style links found; use GitHub Wiki Markdown links instead." >&2
  status=1
fi

while IFS= read -r url; do
  target=${url#"$wiki_base_url/"}
  matches=$(find "$wiki" -type f -name "$target.md" -print)
  match_count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)
  if [ "$match_count" -ne 1 ]; then
    echo "Broken GitHub Wiki link: $url" >&2
    status=1
  fi
done < <(rg --no-filename --only-matching 'https://github\.com/Mungert69/NetworkMonitorLLM/wiki/[[:alnum:]_.\/-]+' "$wiki")

while IFS= read -r page; do
  relative=${page#"$wiki/"}
  case "$relative" in
    index.md|log.md) continue ;;
  esac
  slug=${relative##*/}
  slug=${slug%.md}
  if ! rg --fixed-strings --quiet "]($wiki_base_url/$slug)" "$index"; then
    echo "Not indexed: $relative" >&2
    status=1
  fi
done < <(find "$wiki" -type f -name '*.md' | sort)

if [ "$status" -eq 0 ]; then
  echo "Wiki lint passed."
fi
exit "$status"

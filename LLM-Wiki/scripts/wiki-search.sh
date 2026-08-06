#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: $(basename "$0") <search terms>" >&2
  exit 64
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rg --ignore-case --line-number --context 2 --glob '*.md' -- "$*" "$root/wiki"

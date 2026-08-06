#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

find "$root" \
  -path "$root/LLM-Wiki" -prune -o \
  -path "$root/.git" -prune -o \
  -path "$root/bin" -prune -o \
  -path "$root/obj" -prune -o \
  -type f -print | sort

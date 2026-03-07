# Qwen3.5 llama.cpp Patch Set

This folder contains two local patches for `llama.cpp` to fix Qwen3.5 session/cache behavior.

## Files

- `qwen35_mrope_kv_restore_fix.diff`
- `qwen35_session_tokens_insert_fix.diff`

## What They Fix

1. `qwen35_mrope_kv_restore_fix.diff`
- Target file: `src/llama-kv-cache.cpp`
- Fix: Restores extended KV cell metadata (`llama_kv_cell_ext`) for M-RoPE models during full state/session load.
- Symptom fixed: Session restore failures such as invalid `seq_id` / KV restore errors.

2. `qwen35_session_tokens_insert_fix.diff`
- Target file: `tools/completion/completion.cpp`
- Fix: Corrects token append range from `embd.begin(), embd.begin()` to `embd.begin(), embd.end()`.
- Symptom fixed: Session token tracking not advancing correctly after prompt batch decode.

## Apply Instructions

Run from your `llama.cpp` repo root:

```bash
cd /home/mahadeva/code/models/llama.cpp

# Optional dry-run checks
git apply --check ../patches/qwen35_mrope_kv_restore_fix.diff
git apply --check ../patches/qwen35_session_tokens_insert_fix.diff

# Apply
git apply ../patches/qwen35_mrope_kv_restore_fix.diff
git apply ../patches/qwen35_session_tokens_insert_fix.diff
```

## Verify Patch Applied

```bash
git -C /home/mahadeva/code/models/llama.cpp diff -- src/llama-kv-cache.cpp tools/completion/completion.cpp
```

## Rebuild

Rebuild `llama-completion` (or full project) using your normal build command.

Example:

```bash
cmake --build /home/mahadeva/code/models/llama.cpp/build -j
```

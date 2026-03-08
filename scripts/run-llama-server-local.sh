#!/usr/bin/env bash
set -euo pipefail

# Local llama-server launcher for NetworkMonitorLLM (OpenAI-compatible API).
# Supports:
# - tool calling via chat template/jinja
# - multimodal (when mmproj is provided)
# - slot-based KV cache reuse and optional slot persistence

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${LLAMA_SERVER_ENV_FILE:-$SCRIPT_DIR/../.llama-server.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$ENV_FILE"
fi

LLAMA_SERVER_BIN="${LLAMA_SERVER_BIN:-/home/mahadeva/code/models/llama.cpp/llama-server}"
MODEL_PATH="${MODEL_PATH:-/home/mahadeva/code/models/Qwen3.5-0.8B-q5_0.gguf}"
MMPROJ_PATH="${MMPROJ_PATH:-}"
SLOT_SAVE_PATH="${SLOT_SAVE_PATH:-/home/mahadeva/code/models/llama-slots}"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8082}"
CTX_SIZE="${CTX_SIZE:-12000}"
N_PREDICT="${N_PREDICT:--1}"
THREADS="${THREADS:-4}"
THREADS_BATCH="${THREADS_BATCH:-4}"
PARALLEL_SLOTS="${PARALLEL_SLOTS:-1}"
TEMP="${TEMP:-0.3}"
SLOT_PROMPT_SIMILARITY="${SLOT_PROMPT_SIMILARITY:-0.10}"
REASONING_FORMAT="${REASONING_FORMAT:-none}"

API_KEY="${API_KEY:-}"
API_KEY_FILE="${API_KEY_FILE:-}"

if [[ ! -x "$LLAMA_SERVER_BIN" ]]; then
  echo "llama-server not found or not executable: $LLAMA_SERVER_BIN" >&2
  exit 1
fi

if [[ ! -f "$MODEL_PATH" ]]; then
  echo "Model not found: $MODEL_PATH" >&2
  exit 1
fi

mkdir -p "$SLOT_SAVE_PATH"

args=(
  --host "$HOST"
  --port "$PORT"
  -m "$MODEL_PATH"
  -c "$CTX_SIZE"
  -n "$N_PREDICT"
  -t "$THREADS"
  -tb "$THREADS_BATCH"
  -np "$PARALLEL_SLOTS"
  --slot-prompt-similarity "$SLOT_PROMPT_SIMILARITY"
  --slots
  --slot-save-path "$SLOT_SAVE_PATH"
  --jinja
  --cont-batching
  --metrics
  --no-webui
  --reasoning-format "$REASONING_FORMAT"
  --temp "$TEMP"
)

if [[ -n "$MMPROJ_PATH" ]]; then
  if [[ ! -f "$MMPROJ_PATH" ]]; then
    echo "mmproj file not found: $MMPROJ_PATH" >&2
    exit 1
  fi
  args+=(--mmproj "$MMPROJ_PATH")
fi

if [[ -n "$API_KEY_FILE" ]]; then
  args+=(--api-key-file "$API_KEY_FILE")
elif [[ -n "$API_KEY" ]]; then
  args+=(--api-key "$API_KEY")
fi

echo "Starting llama-server:"
echo "  BIN=$LLAMA_SERVER_BIN"
echo "  MODEL=$MODEL_PATH"
echo "  HOST=$HOST PORT=$PORT"
echo "  CTX=$CTX_SIZE THREADS=$THREADS/$THREADS_BATCH SLOTS=$PARALLEL_SLOTS"
if [[ -n "$MMPROJ_PATH" ]]; then
  echo "  MMPROJ=$MMPROJ_PATH"
fi
echo

exec "$LLAMA_SERVER_BIN" "${args[@]}"

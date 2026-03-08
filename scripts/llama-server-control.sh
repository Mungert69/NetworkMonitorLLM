#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="${RUNNER:-$SCRIPT_DIR/run-llama-server-local.sh}"
ENV_FILE="${LLAMA_SERVER_ENV_FILE:-$SCRIPT_DIR/../.llama-server.env}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$ENV_FILE"
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8082}"
LOG_FILE="${LLAMA_SERVER_LOG_FILE:-/tmp/llama-server-local.log}"
PID_FILE="${LLAMA_SERVER_PID_FILE:-/tmp/llama-server-local.pid}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <start|stop|restart|status|logs>
  start   Start llama-server in background
  stop    Stop llama-server for host=$HOST port=$PORT
  restart Restart llama-server
  status  Show process + endpoint + memory status
  logs    Tail server log
EOF
}

find_pids() {
  pgrep -f "llama-server --host ${HOST} --port ${PORT}" || true
}

start_server() {
  local pids
  pids="$(find_pids)"
  if [[ -n "$pids" ]]; then
    echo "llama-server already running on ${HOST}:${PORT}"
    echo "$pids"
    return 0
  fi

  echo "Starting llama-server..."
  nohup "$RUNNER" >>"$LOG_FILE" 2>&1 &
  local pid=$!
  echo "$pid" > "$PID_FILE"
  sleep 1

  if kill -0 "$pid" 2>/dev/null; then
    echo "Started. PID=$pid"
  else
    echo "Start failed. Check logs: $LOG_FILE"
    tail -n 60 "$LOG_FILE" || true
    return 1
  fi
}

stop_server() {
  local pids=""

  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      pids="$pid"
    fi
  fi

  if [[ -z "$pids" ]]; then
    pids="$(find_pids)"
  fi

  if [[ -z "$pids" ]]; then
    echo "llama-server is not running on ${HOST}:${PORT}"
    return 0
  fi

  echo "Stopping llama-server PID(s): $pids"
  kill $pids 2>/dev/null || true

  for _ in $(seq 1 20); do
    sleep 0.5
    local remaining
    remaining="$(find_pids)"
    if [[ -z "$remaining" ]]; then
      echo "Stopped."
      rm -f "$PID_FILE"
      return 0
    fi
  done

  echo "Force stopping PID(s): $(find_pids)"
  kill -9 $(find_pids) 2>/dev/null || true
  rm -f "$PID_FILE"
}

status_server() {
  local pids
  pids="$(find_pids)"
  if [[ -n "$pids" ]]; then
    echo "Process: RUNNING (${HOST}:${PORT}) PID(s): $pids"
  else
    echo "Process: STOPPED (${HOST}:${PORT})"
  fi

  if curl -fsS --max-time 2 "http://${HOST}:${PORT}/v1/models" >/dev/null 2>&1; then
    echo "API: UP"
    curl -sS --max-time 2 "http://${HOST}:${PORT}/v1/models" | sed -n '1,120p'
  else
    echo "API: DOWN"
  fi

  echo "--- Memory ---"
  free -h | sed -n '1,3p'
}

case "${1:-}" in
  start)
    start_server
    ;;
  stop)
    stop_server
    ;;
  restart)
    stop_server
    start_server
    ;;
  status)
    status_server
    ;;
  logs)
    touch "$LOG_FILE"
    tail -n 120 -f "$LOG_FILE"
    ;;
  *)
    usage
    exit 1
    ;;
esac


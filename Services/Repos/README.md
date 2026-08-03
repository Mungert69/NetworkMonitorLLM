# Repos

Repository/adaptor layer for NetworkMonitorLLM. Encapsulates persistence or
external API access behind interfaces.

## Conversation persistence

`IHistoryStorage` is the shared Redis-backed history store used by `TurboLLM`
and `HugLLM`. Those API-backed runners can reconstruct a request from portable
chat messages, so their histories may be listed or resumed by another service.

`ILocalLlmSessionStore` / `LocalLlmSessionStore` is intentionally separate for
`TestLLM`. It stores one JSON record per session at
`/data/networkmonitor/sessions` by default (configurable through
`LOCAL_LLM_SESSION_PATH`). A record contains:

- `HistoryDisplayName.History` for frontend replay and history display;
- `HistoryDisplayName.LocalLlmContext`, the exact text sent to the local
  llama.cpp process during completed turns.

The factory selects the store by runner type: TestLLM reads, saves, and deletes
only through the local store; TurboLLM and HugLLM continue to use Redis. The
local store writes a temporary JSON file and atomically replaces the prior
record to avoid a partially-written session file.

Because the local context belongs to the Space's mounted `/data`, a TestLLM
session must be resumed or deleted on the same TestLLM server that created it.
The resume caller must use the normal `StartProcess` request before sending the
`<|REPLAY_HISTORY|>` control message; input delivery does not start runners.

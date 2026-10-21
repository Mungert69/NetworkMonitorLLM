# Chat setup and WebSocket protocol

This documents the existing behaviour of `LLMService`, `RabbitListener`, and
`ToolsBuilders/MessageHelper`. It describes independent events; there is no
fixed client-visible startup sequence.

## Worker setup

The routing backend requests startup through `llmStartSession{expert}`.
`LLMService.StartProcess` waits for history initialization, creates and starts a
runner when necessary, and registers its session before publishing
`llmServiceStarted`. An existing usable runner can acknowledge startup without
publishing another starting message or greeting.

Startup status text is published separately through `llmServiceMessage`.
`MessageHelper` prefixes successful status messages, including the monitor's
greeting, with `</llm-success>`. These are notifications, not assistant
conversation text.

The routing backend consumes status and startup acknowledgement through
different RabbitMQ queues. Publishing status first does not guarantee that the
client receives it before readiness. Do not use the greeting or the last
startup notification as a readiness condition.

## Client-visible meaning

The backend sends `</llm-ready>` as a standalone WebSocket text message when it
processes the primary's startup acknowledgement and has an open session socket.
It means the primary is available for requests. It does not mean every expert
is ready, all notifications have arrived, history replay has finished, or a
chat response has ended.

Both of these arrival orders are compatible with the existing clients:

```text
success notification -> llm-ready -> history/conversation messages
llm-ready -> delayed success notification -> history/conversation messages
```

## Message boundaries and classification

Preserve complete WebSocket messages. Reassemble transport fragments before
classification; do not concatenate notification, control, and conversation
messages into a single string and then look for tags.

| Payload | Meaning |
| --- | --- |
| Exactly `</llm-ready>` | Primary readiness control event; not displayed as text. |
| Prefix `</llm-success>`, `</llm-info>`, `</llm-warning>`, or `</llm-error>` | Notification text after the prefix; separate from conversation output. |
| Exactly `<end-of-line>` | End of processing indicator, separate from setup readiness. |
| Conversation text/chunks | Accumulate for conversation rendering after classifying control and structured messages. |

These prefix strings are protocol markers, not balanced XML/HTML tags.
The monitor greeting is a success notification even though its wording sounds
like an assistant utterance.

The React and Razor clients queue `<|REPLAY_HISTORY|>` for initialization and
release it on readiness. Conversation output after readiness is expected.
Repeated readiness is a state update, not a request to clear the conversation
or replay history again. A transient reconnect preserves the existing display;
an explicit reset is a separate operation.

Startup failure can produce an error notification without readiness. The
current protocol has no universal 20-second setup timer, setup sequence number,
or separate `socket-ready` event. It does not recover response chunks missed
during disconnection.

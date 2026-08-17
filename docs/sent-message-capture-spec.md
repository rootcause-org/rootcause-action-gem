# Sent-Message Capture Spec (gem side)

**Status:** ready to build · **Repo:** `rootcause-embassy` (the gem) · **Consumer spec:** `kampadmin/docs/specs/rootcause-sent-message-capture.md` · **Host spec:** `rootcause/docs/specs/sent-message-capture.md` (§ "Gem-facing route"). Build in lockstep — one shared wire contract (§3).

## 1. Intent

Add a fire-and-forget gem method so a consuming app can hand the rootcause host **the actual
reply a human agent sent to a customer** (after editing rootcause's proposed draft). The host
persists it, keyed to the same `session_id` as the analysis, so a later story can learn the
proposed-vs-sent delta. No analysis here — just transport.

This is the gem-channel analogue of ReplyPen's `sent_capture` lane (ReplyPen has its own direct
webhook path; the gem path is for apps that integrate via `RootCause::Embassy`, e.g.
kampadmin). Both feed the **same** `sent_messages` sink on the host.

## 2. New public method — mirror `start_analysis`

`start_analysis` (`lib/rootcause/embassy/client.rb:36-57`) is the exact precedent: build
payload → normalize → JSON → sign → POST → parse → return struct. Clone that shape.

- **Config** (`config.rb`): add optional `attr_accessor :sent_message_url` (like `trigger_url`).
  No new secret — reuse `config.secret` (the reverse secret). Do **not** add to `validate!`
  (optional capability; only required when actually called).
- **Client** (`client.rb`): add `capture_sent_message(...)` next to `start_analysis`. Reuse the
  private `post(url, raw)` helper (`client.rb:98-105`) → `Signature.sign` + `Http.perform`,
  header `X-Webhook-Signature`. Raise `SentMessageError < StandardError` (new, in `errors.rb`,
  raises to the caller — the caller decides retry/skip; do not swallow) on transport/non-2xx.
- **Facade** (`embassy.rb`): add `.capture_sent_message(...)` delegating to
  `client.capture_sent_message(...)`, mirroring the `.start_analysis` delegation at `:62-64`.
- **Signature** params (Ruby kwargs):

```ruby
RootCause::Embassy.capture_sent_message(
  sent_body:,        # String, required — the actual reply that left the building (markdown/plain)
  session_id:,       # String, required — same session handle used in start_analysis
  proposed_body: nil,# String — what rootcause proposed (for the delta); omit if unknown
  sender: nil,       # String — who sent it (agent label/name)
  metadata: {}       # Hash — EXACTLY { resource_type:, resource_id: }, both Strings; KEYS logged, never values
)
```

- Returns a frozen result struct (`{ ok: true }` or a `SentMessage` struct with the host's id).
- Logging: metadata **keys** only, `session_id`, byte sizes — never bodies or secrets
  (match the `start_analysis` logging discipline).
- No attachments in v1 (text only) — skip the `normalize_attachments` path.

## 3. Wire contract (SHARED — host must match byte-for-byte)

`POST {config.sent_message_url}` (e.g. `https://<host>/analyses/<project>/sent-message`).
Headers: `content-type: application/json`, `X-Webhook-Signature: sha256=<hex HMAC-SHA256 of raw
body, key=config.secret>`. Replay guard via `nonce` + `issued_at` in the body (same scheme the
host already enforces for the analysis trigger). Body:

```json
{
  "type": "sent_message",
  "session_id": "support_ticket-<uuid>",
  "sent": { "body": "what the agent actually sent", "sender": "Astrid" },
  "proposed": { "body": "what rootcause proposed (or omitted)" },
  "metadata": { "resource_type": "SupportTicket", "resource_id": "<uuid>" },
  "nonce": "<uuid>",
  "issued_at": "2026-06-17T10:05:00Z"
}
```

- `session_id` is the **mandatory** join key — it is the same value passed to `start_analysis`,
  so the host joins this sent message to every analysis run of that session.
- `proposed` may be absent (host then treats every human reply as pure signal).
- `type` discriminator = `"sent_message"` (future-proofs the endpoint).
- **`metadata` is NOT free-form here.** Unlike the analysis trigger's opaque bag, this route's
  metadata is exactly `{resource_type, resource_id}`, both **strings** — the host strict-decodes it
  (unknown field → `400`) and uses `resource_id` as the thread id. This is the general rule for the
  trigger direction: **`/analyses/*` routes are strict; the action/result direction is
  tolerant-inbound.**

## 4. Host endpoint (what the gem targets — see host spec for the build)

A new route on rootcause, sibling of the analysis trigger, verified with the project's
**reverse secret** (`projects.action_reverse_secret`) + replay guard, persisting into the shared
`sent_messages` table (the table the ReplyPen path already defines). Detailed in
`rootcause/docs/specs/sent-message-capture.md` → "Gem-facing route". The gem only needs the
URL configured; it does not care about persistence.

## 5. Tests (RSpec, reuse `spec/support/wire.rb`)

- Happy path: stub POST, assert URL, signed `X-Webhook-Signature` round-trips, payload shape
  (`session_id`, `sent.body`, `nonce`, `issued_at`), returns the result struct.
- Missing `sent_message_url` → raises a clear config error before any HTTP.
- Blank `sent_body` or `session_id` → `ArgumentError` before sending.
- Non-2xx / transport error → `SentMessageError` to the caller.
- Logging asserts metadata keys only (no values, no body).

## 6. Out of scope

No analysis, no delta scoring, no attachments, no polling/callback, no result handler. Pure
outbound POST. Significant-vs-trivial gating is the **caller's** job (see kampadmin spec).

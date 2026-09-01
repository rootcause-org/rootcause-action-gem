# Canonical fixtures

One copy. Every language repo and the host **vendor** these and replay them byte-for-byte.

## Invariants of this directory

- **Every `.json` fixture is written with NO trailing newline.** The bytes in the file are the bytes
  on the wire. `git diff` will look odd; that is correct and load-bearing — a trailing newline breaks
  every signature.
- `signing_vectors.json` and this README are ordinary files (newline-terminated). They are *about*
  the fixtures, not *on* the wire.
- Signatures are **regenerated**, never hand-edited. Change a fixture → regenerate its vector.

## Fixed test values

| | value |
|---|---|
| `action_reverse_secret` | `contract-reverse-secret` |
| `webhook_secret` (chat) | `contract-chat-secret` |
| reference clock | `2026-06-20T00:00:00Z` = `1781913600` |
| freshness window | ±300s |
| project_id | `11111111-1111-1111-1111-111111111111` |
| tenant_id | `22222222-2222-2222-2222-222222222222` |
| run / analysis id | `33333333-3333-3333-3333-333333333333` |
| session_id | `44444444-4444-4444-4444-444444444444` |
| script | `{ found: true, email: params[:email] }` |
| digest | `sha256:3932d2ca27f8fbf9fd05be71c099fa4a2c2241d0ea64683e542f5f0f3438d7bd` |

Every `issued_at` is the reference clock. A conformance suite **injects that clock**; it never runs
these against wall time.

The script and its digest are internally consistent: `sha256(script) == digest`, so an implementation
can genuinely exercise the digest-verification path with `fetch_response.json`.

## Files

```
signing_vectors.json                    every HMAC vector + the script-fetch query vector
actions/
  invocation_flat.json                  no tenant tuple, no dry_run (dry_run emitted iff true)
  invocation_tenant.json                full tenant tuple
  invocation_principal.json             tenant tuple + host-stamped principal and typed claims
  invocation_dry_run.json               dry_run: true
  script_fetch_query.txt                the RAW query string the GET signature covers
  health_query.txt                      map-mode health GET raw query
  fetch_response.json                   signed script-by-digest response
  result_ok.json                        success envelope
  result_dry_run.json                   {"dry_run":true,"would_execute":true}
  result_refusal_bad_signature.json     401
  result_refusal_replay.json            409
  result_refusal_schema_violation.json  422
  result_refusal_resolve_failed.json    502
  health_response.json                  signed GET {mount}/health
analysis/
  trigger.json                          minimal: no session, no principal, no tenant
  trigger_with_principal.json           principal + session_id + tenant + attachment
  trigger_response.json                 the 202
  result_callback.json                  full surface incl. project_id/executed_actions/questions/delete
  result_ack.json                       the signed 200 ack
  sent_message.json                     proposed vs sent capture
  answers.json                          answers-only variant (no sent body)
chat/
  jwt_vector.json                       secret + claims + iat → the exact token string
  widget_tag.html                       the loader <script> tag, ?v=2
  sse_frames.jsonl                      redacted decoded data frames from one complete SSE turn
```

## What a conformance suite asserts

The full per-plane case list is [`../conformance.md`](../conformance.md); the seven points below are
the spine.

1. **Verify** — for each entry in `signing_vectors.json.bodies`, HMAC-SHA256 the referenced file's
   exact bytes with the listed secret and match `signature`. Also match `body_sha256` and
   `body_bytes` (they catch a newline that snuck in through a checkout or an editor).
2. **Sign** — produce the signature over your own serialization of the same logical message and
   round-trip it through your own verifier. Key order is not contract; only your own bytes matter.
   (The one place order *is* pinned is the script-fetch query string: `action_id`, `digest`,
   `project_id`, in that order.)
3. **Decode** — map every envelope fixture into your own types and assert the field mapping,
   especially `notes[].key == "summary"`, `actions[].slug`, `executed_actions[]`, `questions[]`,
   `delete[]`.
4. **Errors** — assert your status ↔ `class` table against the four refusal fixtures.
5. **Refusal is signed** — assert every non-2xx you produce also carries a valid signature.
6. **Chat** — replay `jwt_vector.json` to the **exact** `token` string, and assert `alg` is checked
   before the signature.
7. **Replay** — a duplicate nonce is `409` on the action route; on the result route it is a `200` ack
   after a successful dispatch, and a real re-dispatch after a failed one (the nonce is released).
8. **Principal** — decode the optional action principal, expose its identity and typed claims only to
   the action invocation, strip inherited `RC_PRINCIPAL_*`, and keep accepting the principal-less
   fixtures unchanged.

Record the hub commit SHA you vendored from, and print it in the suite's output.

---
name: embassy-action-runner
description: Maintain the rootcause Ruby Embassy's signed boundaries — the inbound action invocation route, the inbound analysis-result route, and the outbound trigger/sent-message/API calls. Use when changing wire fields, HMAC/replay handling, schema validation, digest resolution, trusted tenant context, script execution, timeouts/deadlines, the Result surface, or host wire-contract compatibility in rootcause-embassy-ruby.
---

# Embassy (Ruby)

Read `AGENTS.md` and `SPEC.md` completely before changing behavior. For cross-repo changes, also read
the host's `WIRE-CONTRACT.md` and `.agents/skills/actions/SKILL.md` in `rootcause`.

Everything lives under `lib/rootcause/embassy/` (the pre-0.3.0 `lib/rootcause/action_runner/` namespace
is gone). Stdlib only — no runtime dependencies.

## Two inbound routes, deliberately asymmetric

| | invocation (`mount_at`) | result (`result_mount_at`) |
|---|---|---|
| core | `runner.rb` (`Runner`) | `result_rack.rb` (`ResultReceiver`) |
| shell | `rack.rb` (`RackApp`) | `result_rack.rb` (`ResultRackApp`) |
| direction | host → gem, runs an action | host → gem, delivers an analysis result |
| duplicate nonce | **409 replay** | **idempotent signed `200 {"ok":true}` ack** |
| stale `issued_at` | 409 | 409 |

The result route's dedupe is the whole point of the asymmetry: rootcause sends a **stable
`nonce = run_id`** across redeliveries of the same result, so a duplicate is a redelivery to ack, not
an attack to refuse. `Replay.guard!` raises on a seen nonce (invocation); `Replay.fresh?` returns
`false` instead (result). The receiver consumes the nonce *before* dispatch and **releases** it
(`store.delete`, when the store supports it) if dispatch raises, so a refused delivery is still
retryable by the host. Handlers must stay idempotent regardless.

## Trust path (invocation)

- Verify HMAC over raw bytes before JSON parsing (`runner.rb` → `signature.rb`).
- Replay-guard `issued_at` + `nonce`, then validate host-owned fields and model-influenced params.
- Resolve only a signed, digest-matching `script.rb` through `resolver.rb`.
- Execute through `executor.rb`; params stay frozen data. Trusted tenant and optional principal context
  come only from signed top-level fields and are installed during serialized execution.
- Sign every structured result/refusal over the exact response bytes.

Never derive tenant identity from `params`. A bound signed invocation carries `tenant_id` +
`tenant_slug` and may carry `tenant_scope_value`; a flat invocation omits all three to preserve its
original bytes. Tenant-enabled deployments set `require_tenant_context = true`, which rejects an absent
tuple before resolving the script unless its signed `action_id` is explicitly listed in
`tenantless_actions`. That allowlist is for globally unique flat-project actions whose reviewed body
derives its tenant from the target record; partial tuples always refuse, and complete tuples remain
valid. The executor removes stale `RC_TENANT_*` first and installs only
non-empty trusted values, so flat/missing scope stays absent. Reserve both tenant field names and
  `RC_TENANT_*` names from action schemas. The optional principal requires non-empty `kind` and
  `external_id`, plus typed named claims; reserve `principal_kind`, `principal_external_id`, and every
  `RC_PRINCIPAL_*` spelling. The executor clears inherited `RC_PRINCIPAL_*`, exposes a signed principal
  only for its action, then restores the prior process environment. Validate bound ids as non-nil UUIDs,
  slugs with the host's canonical slug rule, and all env-bound values as NUL-free before resolving the script.

**One deadline for the whole invocation.** The host waits ~25s, one shot, no retry, so `Runner#handle`
wraps the entire pipeline (fetch **and** execute) in `config.total_deadline` (22s) and returns the
executor's own timeout-style failure envelope on breach. `config.timeout` (20s) is the execute backstop
*inside* that budget; `validate!` refuses a `total_deadline` that does not exceed it.

## Outbound (client.rb)

- `start_analysis` — signed trigger. Optional `principal:` `{kind:, external_id:, asserted_by:,
  assurance:, tenant_hint:, source_metadata:}`: exact host field names, nils omitted, `kind` +
  `external_id` required together (raises pre-POST). Assert it from the customer app's own
  authenticated session — **never from model output**.
- `capture_sent_message` — `metadata` is exactly `{resource_type, resource_id}` (strings).
- **Direction rule:** trigger-direction routes (`/analyses/*`) are **strict** host-side (unknown field
  → 400); the action/result direction is tolerant-inbound. Never send a speculative field outbound.

## The Result surface (`result.rb`)

Mirrors the host's `webhook.AnalysisResult` verbatim. `actions[]` are **proposals** (render as confirm
buttons); `executed_actions[]` **already ran** mid-loop under the host's autonomy gate (render as
outcomes — never buttons); `questions[]` are answered back over `capture_sent_message`; `delete_ids`
is the wire's reserved-word `delete` (note keys the run retracts). `reasoning_steps` was gem-only
fiction and is deleted — the host never sent it.

## File map

- `runner.rb`: authenticated invocation pipeline, trusted host-field validation, total deadline.
- `result_rack.rb`: result route core + Rack shell; idempotent redelivery ack.
- `replay.rb`: ±5 min window, nonce store (`guard!` raises / `fresh?` reports), `MemoryStore`.
- `schema.rb`: action param contract and reserved tenant/principal selectors.
- `resolver.rb`: signed script fetch + digest verification/cache.
- `executor.rb`: compiled Ruby body, trusted `ENV`, invocation-scoped context, execute timeout, stdout, structured failure.
- `client.rb`: outbound trigger + sent-message capture.
- `config.rb`: every knob, validated fail-closed at boot.
- `spec/support/wire.rb`: Ruby-side host fixture builder; keep it aligned with host goldens.
- `spec/fixtures/contract/`: vendored canonical goldens — synced from the contract hub, not hand-edited.

## Verification

Run `bundle exec rake` (StandardRB + all RSpec). For wire changes, cover exact signed success,
tampering, missing/malformed fields, flat context, and param/host separation.

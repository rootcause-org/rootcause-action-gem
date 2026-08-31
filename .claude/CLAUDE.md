# rootcause-embassy (the **Embassy**, Ruby)

> Renamed from `rootcause-action-runner` / `RootCause::ActionRunner` (≤ 0.2.0) → `rootcause-embassy`
> / `RootCause::Embassy` (0.3.0+). Repo: `rootcause-embassy-ruby` (per-language polyrepo; PHP/Node/.NET
> Embassies are separate `rootcause-embassy-<lang>` repos).

A **thin Ruby gem** the customer mounts once in their Rails app — the **Embassy**, rootcause's trusted
in-app presence and the first **action runner** in rootcause's **action plane**. It receives a signed,
digest-pinned **invocation** from the rootcause host, **resolves the action's script by digest**, runs
it **inline with a hard timeout**, returns a **signed structured result**, and **receives
async-analysis results** — all using the customer's own env, code, and tooling. No executable code
ever travels on the wire.

**The authoritative design for this gem is [SPEC.md](SPEC.md). Read it before changing behavior.**
The whole-plane design lives in
[`rootcause/docs/action-plane-spec.md`](https://github.com/rootcause-org/rootcause/blob/main/docs/action-plane-spec.md)
— read that first for the host side (registry, signer, confirm/execute pages, audit).

## Stage

Scaffold + spec, **no implementation yet, no users**. Refactor freely — no backward-compat, no shims,
delete dead code, rename freely. First customer: **Momentum Tools** (a *self-owned* project, so full
delegation is fine; the customer-held approval allowlist is a launch blocker only for the first
non-self-owned customer).

## What we do / what we don't

**We do:** verify a signed invocation (HMAC-SHA256 over raw body, constant-time) → replay-guard
(±5 min window + unseen nonce) → validate params against the carried schema → **resolve the script by
digest** (cache hit if `sha256 == digest`, else fetch from rootcause and verify before running) →
execute inline with a hard timeout, params bound **as data** → return signed structured JSON
(`{ ok, return_value | error, stdout?, duration_ms }`) → log customer-side.

**We don't** (out of scope — push back if asked):
- **No arbitrary-Ruby mode.** Only a body whose `sha256` equals the approved `script_digest` ever
  runs. Digest mismatch is a hard refuse.
- **No sandbox claims.** The gem runs as the app with full privileges; safety is approved +
  digest-pinned scripts, signature + replay, params-as-data, audit. Real isolation is a later swap.
- **No registry / approval logic** — that is the host's. The gem only verifies and runs.
- **No async / job queue / callbacks of its own** — inline and synchronous.
- **No sending email** — the human-reviewed draft is rootcause's concern.
- **No non-Ruby runners, no large-output/download URLs, no dry-run** in v1 (the contract is ready).

## Taxonomy (shared verbatim with rootcause / ReplyPen)

One word per concept. Use the **bold** term in code, comments, docs, commits, tests; aliases banned.

| Term | Is | Not (banned) |
|---|---|---|
| **action** | A vetted, versioned *script* in rootcause's registry, identified by content **digest** — the capability we run on the customer's own prod app. **Distinct from `tool`** (never call it that). | ~~effect~~, ~~command~~, ~~macro~~ |
| **action runner** | This gem — the customer-side component that **resolves an action by digest**, executes it with a hard timeout, returns a structured result. Contract is language-agnostic; Ruby is first. | ~~plugin~~, ~~agent~~ |
| **action run** | One proposed/executed invocation of an action for a thread (`proposed → executing → succeeded`/`failed`). Audited host-side in `action_runs`. | ~~invocation~~ (that's the wire message), ~~call~~ |
| **invocation** | The signed wire message rootcause POSTs to the gem: `action_id + params + script_digest + schema + nonce + issued_at`. **No script body.** | — |
| **digest** | `sha256(script.rb)` — the action's pinned identity and the **authorization unit**. The gem runs a body iff its hash equals the digest in the invocation. | ~~hash~~ (in prose ok, but `digest` in code) |
| **reverse-channel secret** | The per-project HMAC secret for this channel — **distinct** from the email `webhook_secret`. Held in KMS host-side; the gem holds its copy via `ENV`. | ~~webhook_secret~~ |

## Tooling rules (PJ's box)

- **Ruby:** `bundler` for deps, **`mise`** for the Ruby version (check `mise.toml`). Standard gem
  workflow (`bundle`, `rake`, `rspec`). No rbenv/rvm/asdf.
- **No new runtime deps without a recorded reason.** Prefer stdlib: `Net::HTTP` for the script fetch,
  `OpenSSL::HMAC` + `Digest::SHA256` for signing/digest, `Timeout` for the backstop.
- HMAC compare must be **constant-time** (`OpenSSL.fixed_length_secure_compare` / `Rack::Utils.secure_compare`).

## Conventions & key decisions

- **Refactor freely; no backward-compat** while pre-implementation. No shims/flags.
- **Fail closed everywhere:** bad signature, stale/duplicate nonce, schema violation, digest mismatch,
  fetch non-2xx → refuse, return a structured error, log it.
- **Tenant scope is host-owned.** Every signed invocation carries `tenant_id`, `tenant_slug`, and
  `tenant_scope_value` when bound; flat runs omit them to preserve the original wire bytes. The runner
  installs non-empty trusted values as `RC_TENANT_*` only while the script runs, removing stale values
  for flat/missing scope. Tenant selectors are forbidden params. Tenant-enabled deployments set
  `require_tenant_context = true` so an absent tuple refuses before resolution. A deployment spanning
  a genuinely flat sibling may exempt globally unique signed action ids via `tenantless_actions`;
  partial tuples remain invalid and every non-allowlisted action stays strict.
- **Params are data, never source.** Bind `params` as a frozen, symbol-keyed hash; compile the body
  once; capture its last expression as the JSON-able return value. A param value must never be
  interpolated into evaluated source.
- **`Timeout.timeout` is a backstop, not a transaction boundary** — it raises asynchronously and can
  fire mid-transaction. Actions are written idempotent + retry-safe; the gem enforces the timeout and
  reports failure cleanly, nothing more.
- **Secrets never in logs / argv / responses.** Log `action_id`, `digest`, param **keys**, `ok`,
  `duration_ms` — never the secret or param values.
- **Keep the core framework-agnostic.** verify → validate → resolve → run → sign is plain Ruby; the
  Rails glue is a thin shell so a Sinatra/Rack host could reuse it.
- **Code comments: high signal-to-noise.** Explain *why* — intent, invariants, gotchas. No changelog
  narration; git log is the source of truth.
- **Diagrams: always Mermaid, never ASCII art.**

## Before reporting done

- `bundle exec rake` (lint + `rspec`) — fix issues before finishing.
- **Always commit when a task is done** — commit the files *you* touched without being asked, even for
  a solo edit. Don't leave finished work uncommitted.
- **Parallel agents on `main`** (no feature branches): commit the files you touched, leave others'
  in-flight changes alone, verify you're on `main` before committing routine work.

# rootcause-embassy — rootcause's in-app presence in the customer's Ruby runtime

> **Renamed:** formerly `rootcause-action-runner` / `RootCause::ActionRunner` (≤ 0.2.0); now
> `rootcause-embassy` / `RootCause::Embassy` (0.3.0+). Repo is `rootcause-embassy-ruby` — the
> per-language Ruby Embassy.

A **thin Ruby gem** the customer mounts once in their Rails app — the **Embassy**, rootcause's
trusted in-app presence and the **first action runner** in rootcause's **action plane**. It receives
a signed **invocation** from the rootcause host, **resolves the action's script by digest**, runs it
**inline with a hard timeout**, returns a **signed structured result**, and **receives async-analysis
results**. No executable code ever travels in the invocation; the gem only runs a script whose
`sha256` equals the approved `script_digest`.

> **This repo is the gem only.** The host (registry, signer, confirm/execute pages, audit) lives in
> [`rootcause`](https://github.com/rootcause-org/rootcause). The authoritative design for
> the whole plane is
> [`docs/action-plane-spec.md`](https://github.com/rootcause-org/rootcause/blob/main/docs/action-plane-spec.md)
> in that repo — **read it first**; this SPEC narrows it to the runner's responsibilities and the
> wire contract the gem must honor.

**Status:** scaffold + spec (no implementation yet). This document is the build plan.

---

## 1. What the gem is (and is not)

**It is** a synchronous, single-route HTTP component that turns a signed, digest-pinned invocation
into a structured result, running **as the host Rails app** with full app privileges.

**It is not** (push back if asked):
- **Not an arbitrary-Ruby executor.** It runs only a body whose `sha256` matches the approved
  `script_digest` in the signed invocation. A mismatch is a hard refuse.
- **Not a sandbox.** It runs in-process with app privileges. Safety comes from: approved +
  digest-pinned scripts only, signature + replay on the channel, params bound as **data** (never
  interpolated into source), and dual-sided audit. Real isolation is a later runtime swap.
- **Not a registry / approver.** The gem never decides what is allowed; it verifies the signature and
  the digest, fetches an approved body from rootcause on a cache miss, and runs it.
- **Not async.** Inline, synchronous, with a hard timeout. No job queue, no callbacks of its own.
- **Not a sender.** It returns a result to rootcause; the human-reviewed email draft is rootcause's
  concern, never the gem's.

## 2. Where it sits in the plane

```mermaid
flowchart LR
    subgraph rc["rootcause host"]
        signer[internal/action<br/>KMS HMAC · sign invocation · serve script-by-digest]
        egress[internal/egress<br/>allowlist + log]
    end
    subgraph cust["customer Rails app"]
        route[mounted route<br/>POST /rootcause/action]
        runner["RootCause::Embassy<br/>verify sig + replay → validate params →<br/>resolve script by digest → run (timeout) → sign result"]
        cache[(script cache<br/>digest → script.rb)]
    end
    signer -->|signed invocation<br/>action_id + params + digest · NO code| egress
    egress --> route --> runner
    runner -. cache miss: GET script by digest .-> signer
    runner --> cache
    runner -->|signed result / error+backtrace| signer
```

The gem only ever talks to **one** rootcause origin (configured `fetch_url` host). It accepts
invocations signed with the **per-project reverse-channel secret** (distinct from the email
`webhook_secret`).

## 3. Responsibilities, in order (the request path)

A single mounted handler does exactly this, fail-closed at every step:

1. **Verify** the invocation signature — `X-Webhook-Signature: sha256=<hex>` over the **raw** body,
   HMAC-SHA256 with the configured reverse-channel `secret`, **constant-time** compare.
2. **Replay-guard** — reject if `issued_at` is outside a ±5 min window, or if `nonce` has been seen
   (bounded in-memory / cache store of recent nonces).
3. **Validate params** against the `schema` carried in the invocation (defense in depth — rootcause
   already validated at propose-time). Types: `string`, `integer`, `number`, `boolean`, `string[]`.
4. **Resolve the script by digest:**
   - **Cache hit** — a cached `script.rb` whose `sha256 == script_digest` → use it.
   - **Cache miss** — `GET {fetch_url}?action_id=…&digest=…` (signed the same way), **verify
     `sha256(body) == script_digest`** before caching or running. Digest mismatch / non-2xx → hard
     refuse, fail closed.
5. **Bind + execute** — params as a **frozen, symbol-keyed hash**, passed **as data, never
   interpolated into source**. Compile the body once into a callable that receives `params`; its last
   expression is the (JSON-serializable) return value.
6. **Hard timeout** + **rescue everything** → structured `error{class, message, backtrace}`.
7. **Return signed JSON** — `{ ok, return_value | error, stdout?, duration_ms }`, signed with the
   reverse-channel secret. **Log customer-side**: `action_id`, `digest`, param **keys** (never
   values), `ok`/`err`, `duration_ms`. Never log the secret or param values.

## 4. Public API (what the customer writes)

```ruby
# Gemfile
gem "rootcause-embassy"
```

```ruby
# config/initializers/rootcause.rb
RootCause::Embassy.configure do |c|
  c.secret    = ENV.fetch("ROOTCAUSE_ACTION_SECRET")    # reverse-channel HMAC secret (per project)
  c.mount_at  = "/rootcause/action"                     # the single route
  c.fetch_url = "https://<rootcause>/actions/script"    # script-by-digest endpoint
  c.timeout   = 20                                       # hard per-run timeout (seconds)
  c.logger    = Rails.logger
end
```

Mounting (Rails): the gem exposes a Rack app / engine route at `mount_at`. The customer adds **one
line** (or the gem auto-mounts via a Railtie — decide in §8). The recommendation, documented but not
enforced in v1, is to **restrict the route to rootcause's egress IP** at the edge and run under a
**least-privileged DB role** where feasible.

## 5. Wire contract (must match the host verbatim)

The gem implements the **customer side** of Appendix A of the action-plane spec. Three messages, all
signed with the reverse-channel secret, verify-on-raw, constant-time:

**Invocation** (rootcause → gem), `POST {mount_at}` — **no script body**:

```jsonc
{
  "action_id":     "devise_send_password_reset",
  "script_digest": "sha256:…",                    // the exact approved version the gem must run
  "params":        { "email": "x@acme.com" },     // validated, typed
  "schema":        { /* manifest param schema, for gem-side re-validation */ },
  "runtime":       "ruby",
  "project_id":    "uuid",
  "nonce":         "uuid",                          // replay id
  "issued_at":     "2026-06-03T10:00:00Z"          // ±5 min window
}
```

**Script fetch** (gem → rootcause, on cache miss), `GET {fetch_url}?action_id=…&digest=…` — signed:

```jsonc
{ "action_id": "…", "digest": "sha256:…", "script": "user = User.find_by(...)…", "runtime": "ruby" }
```

The gem **verifies `sha256(script) == digest`** before caching or running. Unknown/unapproved digest
→ rootcause returns 404 → the run **fails closed**.

**Result** (gem → rootcause) — signed:

```jsonc
{ "ok": true, "return_value": { "found": true, "sent_to": "x@acme.com" },
  "stdout": "", "error": null, "duration_ms": 142 }
```

Rules: sign-then-send / verify-on-raw; constant-time compare; reject on bad signature, stale
`issued_at`, seen `nonce`, or digest mismatch. Oversize output is truncated (inline JSON only — no
files / download URLs in v1).

## 6. The action body it runs (read-only context)

The gem **never authors** actions; it only runs them. For reference, an action in rootcause's
registry is one directory `brain/actions/<action_id>/` with `manifest.yaml` (id, description, typed
param schema, risk hint) and `script.rb`. The script references `params[:x]` and returns a JSON-able
value:

```ruby
# script.rb — params is a frozen, symbol-keyed hash of VALIDATED values.
# NEVER interpolate params into source; reference them as data.
user = User.find_by(email: params[:email])
return { found: false } unless user
user.send_reset_password_instructions
{ found: true, sent_to: user.email }
```

`digest = sha256(script.rb)` is the action's pinned identity and the **authorization unit**. The gem
runs a body **iff** its hash equals the digest in the signed invocation.

## 7. Security posture / honest caveats

- Runs **as the app**, full privileges — **no real sandbox**. The boundary is: approved +
  digest-pinned scripts only, signature + replay, params-as-data, audit.
- **`Timeout.timeout` is a backstop, not a transaction boundary.** It raises asynchronously and can
  fire mid-transaction. Actions must be written **idempotent and safe to retry**, ideally wrapping
  their own `transaction`. The gem's job is to enforce the timeout and report failure cleanly, not to
  guarantee atomicity.
- **Params are data, never source.** Compile the body once; bind `params` as a frozen symbol-keyed
  hash. A param value like `"; system('rm -rf /')"` must be inert — a string, never evaluated.
- **Fail closed everywhere:** bad signature, stale/duplicate nonce, schema violation, digest mismatch,
  fetch non-2xx → refuse, return a structured error, log it.
- **Secrets never in logs / argv / responses.** Log param **keys** only.

## 8. Build plan (decide as we implement — NOT done yet)

Open scaffolding decisions to settle when we start coding:

- **Mount mechanism** — Rails Engine vs. a Rack app the customer mounts in `routes.rb` vs. a Railtie
  that auto-inserts the route. Lean: explicit mount (least magic, easiest to restrict at the edge).
- **Script execution** — `instance_exec` / compiled proc / `Module.new` + `define_method`. Must bind
  `params` as data and capture the last expression as the return value. Decide how `stdout` is
  captured (`$stdout` swap vs. `StringIO`).
- **Nonce store** — process-memory ring buffer (single worker) vs. Rails.cache / Redis (multi-worker).
  ±5 min window means TTL-bounded.
- **Script cache** — on-disk (`tmp/rootcause/actions/<digest>.rb`) vs. in-memory; keyed by digest so
  it is immutable and self-verifying.
- **HTTP client** for the fetch — `Net::HTTP` (no new dep) preferred.
- **Framework coupling** — keep the core (verify, validate, resolve, run, sign) **framework-agnostic**
  in plain Ruby; the Rails glue is a thin shell so a Sinatra/Rack host could reuse it.

## 9. Layout (planned — gem skeleton)

```
rootcause-embassy-ruby/
├── rootcause-embassy.gemspec
├── Gemfile
├── Rakefile
├── mise.toml                      # Ruby version (mise-managed)
├── .gitignore
├── AGENTS.md                      # → .claude/CLAUDE.md (symlink)
├── .claude/CLAUDE.md              # agent project instructions (real file)
├── .claude/skills                 # → ../.agents/skills (symlink)
├── .agents/skills/                # real skills dir
├── SPEC.md                        # this file
├── lib/
│   └── rootcause/
│       └── embassy/
│           ├── version.rb
│           ├── config.rb          # the configure block
│           ├── signature.rb       # HMAC sign/verify, constant-time
│           ├── replay.rb          # ±5 min window + nonce store
│           ├── schema.rb          # param-type validation
│           ├── resolver.rb        # resolve-by-digest: cache hit / fetch + verify
│           ├── executor.rb        # bind params as data, run, timeout, rescue
│           └── rack.rb            # the mounted handler (verify → … → sign result)
└── spec/                          # RSpec
```

## 10. Testing (mirrors action-plane-spec §15, "Gem (Ruby)" row)

| Area | What |
|---|---|
| **Signature** | `Sign`/`Verify` round-trip; constant-time; forged/missing signature rejected. |
| **Replay** | `issued_at` outside ±5 min rejected; repeated `nonce` rejected; fresh nonce accepted. |
| **Schema** | each type (`string`/`integer`/`number`/`boolean`/`string[]`); missing required → reject; wrong type → reject. |
| **Resolve-by-digest** | cache hit uses cached body; cache miss → fetch + verify; **digest mismatch → hard refuse** (never runs). |
| **Param binding is data** | a param value `"; system('x')"` cannot execute — it is an inert string. |
| **Timeout** | a hanging body is killed by the hard timeout and returns a structured error. |
| **Errors** | any raised exception → structured `error{class, message, backtrace}`; return value must be JSON-able (non-serializable → error). |
| **Logging** | logs `action_id`/`digest`/param **keys**/`ok`/`duration_ms`; never the secret or param values. |

Test with RSpec; stub the rootcause origin (signature + script-fetch) so the gem suite needs no live
host.

## 11. Out of scope (v1)

Inherited from the action-plane spec §16: no non-Ruby runners (contract is ready), no large-output /
download URLs, no dry-run, no idempotency keys beyond the nonce, no customer-side approval gate (that
is rootcause's per-run human gate today; the **customer-held allowlist** is the launch blocker for the
first non-self-owned customer), no stronger isolation than `Timeout.timeout` yet.

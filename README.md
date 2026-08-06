# rootcause-embassy

> **Renamed:** this gem was `rootcause-action-runner` (namespace `RootCause::ActionRunner`) ≤ 0.2.0.
> It is now **`rootcause-embassy`** / `RootCause::Embassy` as of 0.3.0.

The **Embassy** is rootcause's trusted, in-app presence inside the customer's own Rails/Rack
runtime — the far end of the reverse channel. It **executes actions** (receives a signed,
digest-pinned **invocation** from the rootcause host, **resolves the action's script by digest**,
runs it **inline with a hard timeout**, returns a **signed structured result**) and **receives
async-analysis results**, all using the customer's own env, code, and tooling. No executable code
ever travels on the wire. This Ruby gem is the first manifestation; PHP/Node/.NET Embassies ship as
their own per-language repos (`rootcause-embassy-<lang>`).

> The authoritative design is [SPEC.md](SPEC.md). The whole-plane design (host side: registry,
> signer, confirm/execute pages, audit) lives in
> [`rootcause/docs/action-plane-spec.md`](https://github.com/rootcause-org/rootcause/blob/main/docs/action-plane-spec.md).

## Install

```ruby
# Gemfile
gem "rootcause-embassy"
```

## Configure

```ruby
# config/initializers/rootcause.rb
RootCause::Embassy.configure do |c|
  c.secret    = ENV.fetch("ROOTCAUSE_ACTION_SECRET") # reverse-channel HMAC secret (per project)
  c.fetch_url = "https://<rootcause>/actions/script" # script-by-digest endpoint
  c.timeout   = 20                                   # hard per-run timeout (seconds)
  c.require_tenant_context = true                    # REQUIRED on tenant-enabled projects
  c.logger    = Rails.logger
end
```

`configure` validates fail-closed at boot: a missing `secret` or `fetch_url` raises immediately.

Tenant-enabled Embassy deployments **must** set `require_tenant_context = true`; this refuses a signed
tenantless invocation before script resolution. Flat deployments leave its default `false` so their
wire remains unchanged. Other tunables (with defaults): `clock_skew` (300s replay window half-width), `cache_dir`
(`tmp/rootcause/actions`, set `nil` for memory-only), `capture_stdout` (true), `max_stdout_bytes`
(64 KiB), `max_backtrace_lines` (50), `http_open_timeout` / `http_read_timeout`.

## Mount

Explicit mount — least magic, easiest to restrict at the edge:

```ruby
# config/routes.rb
mount RootCause::Embassy::RackApp.new => RootCause::Embassy.config.mount_at
```

**Recommended (documented, not enforced in v1):** restrict the route to rootcause's egress IP at the
edge, and run under a least-privileged DB role where feasible.

## What it does, in order (fail-closed at every step)

1. **Verify** `X-Webhook-Signature: sha256=<hex>` over the **raw** body (HMAC-SHA256, constant-time).
2. **Replay-guard** — reject if `issued_at` is outside ±`clock_skew`, or `nonce` was already seen.
3. **Validate trusted tenant context** — signed `tenant_id`, `tenant_slug`, and `tenant_scope_value`
   fields are host-owned; flat runs must omit them, while bound runs require id + slug together.
4. **Validate params** against the `schema` carried in the invocation (defense in depth); tenant
   selector names are reserved and refused.
5. **Resolve the script by digest** — cache hit (`sha256 == digest`) or fetch + verify; mismatch is a
   hard refuse.
6. **Bind + execute** — params as a frozen, symbol-keyed hash, **as data, never interpolated into
   source**; trusted tenant context is available as `RC_TENANT_ID`, `RC_TENANT_SLUG`, and
   `RC_TENANT_SCOPE_VALUE` for the duration of the action.
7. **Hard timeout** + rescue everything → structured `error{class, message, backtrace}`.
8. **Return signed JSON** — `{ ok, return_value | error, stdout, duration_ms }`. Logs `action_id`,
   `digest`, param **keys**, `ok`, `duration_ms` — never the secret or param values.

## Security posture (honest caveats)

- **Not a sandbox.** Runs in-process as the app, full privileges. The boundary is: approved +
  digest-pinned scripts only, signature + replay on the channel, params bound as data, dual-sided
  audit. Real isolation is a later runtime swap.
- **`Timeout.timeout` is a backstop, not a transaction boundary** — it raises asynchronously and can
  fire mid-transaction. Actions must be written idempotent and safe to retry.
- **The digest is the authorization unit.** A body runs **iff** its `sha256` equals the
  `script_digest` in the signed invocation.
- **Tenant scope is host-owned.** Action scripts must scope tenant-aware writes with the applicable
  `RC_TENANT_*` field. `params` cannot carry tenant selectors. Flat runs remove these variables, as
  does an absent/empty optional scope value.

## Async analysis (trigger + result callback)

The opposite direction of the invocation flow, on the **same reverse-channel secret**: your app asks
rootcause to *analyze this* and later receives the drafted answer into a Ruby handler — no polling, no
job rig of your own. The host keeps the conversation history keyed by an opaque **`session_id`**, so a
follow-up sends only the new message — persist the `session_id` and pass it back. See
[docs/async-analysis-spec.md](docs/async-analysis-spec.md).

```ruby
# config/initializers/rootcause.rb — extends the block above
RootCause::Embassy.configure do |c|
  # ... secret / fetch_url as above ...
  c.trigger_url     = "https://<rootcause>/analyses/<project>" # where start_analysis POSTs
  c.result_mount_at = "/rootcause/result"                      # route that receives async results
  c.result_handler  = "AnalysisResultHandler"                  # String → lazy-loaded, reload-safe
  c.max_attachment_bytes = 256 * 1024                          # per-attachment inline cap (decoded)
end
```

```ruby
# config/routes.rb — mount the result route alongside the invocation route
mount RootCause::Embassy::ResultRackApp.new => RootCause::Embassy.config.result_mount_at
```

**Trigger** from a background job (the trigger is a quick signed POST; running it off the request keeps
your controller fast and lets you retry on `TriggerError`):

```ruby
# app/jobs/analyze_ticket_job.rb
class AnalyzeTicketJob < ApplicationJob
  def perform(ticket)
    analysis = RootCause::Embassy.start_analysis(
      subject: ticket.subject,
      body:    ticket.body,                       # plain text only (v1)
      attachments: [{filename: "error.log", mime_type: "text/plain",
                     content_base64: Base64.strict_encode64(ticket.log_file)}],
      metadata: {resource_type: "SupportTicket", resource_id: ticket.id}, # echoed back verbatim
      session_id: ticket.rc_session_id,           # nil on the first turn; set to continue
    )
    ticket.update!(
      rc_analysis_id: analysis.analysis_id,       # persist alongside the resource
      rc_session_id:  analysis.session_id,        # persist too — forward to continue the thread
      analysis_state: :pending,
    )
  end
end
```

A non-2xx / transport failure raises `RootCause::Embassy::TriggerError` (yours to retry); an
over-cap or malformed attachment raises `ArgumentError` before anything is sent.

**Handle the result** — a plain class in `app/`, idempotent (rootcause **redelivers** on a lost ack):

```ruby
# app/rootcause/analysis_result_handler.rb
class AnalysisResultHandler < RootCause::Embassy::ResultHandler
  def process(result)
    return unless result.metadata[:resource_type] == "SupportTicket"
    ticket = SupportTicket.find_by(id: result.metadata[:resource_id]) or return

    if result.decline
      ticket.update!(analysis_state: :declined, analysis_note: result.decline[:reason])
    else
      ticket.update!(analysis_state: :ready,
        ai_draft:        result.draft, # markdown string (the drafted answer)
        ai_note:         result.note,  # markdown string (the summary note)
        rc_session_id:   result.session_id, # persist to continue the thread later
        rc_actions:      result.actions) # human-gated buttons — render, never auto-execute
    end
  end
end
```

`result.draft` and `result.note` are **markdown strings** — `draft` is the drafted answer's
`body_markdown`; `note` is the *summary* note's `body_markdown` (rootcause delivers `notes[]` — one
summary note plus widget notes; the gem surfaces only the summary, whose body carries the run-trace as
a markdown link). HTML is used only as a fallback when markdown is absent. `draft` / `note` /
`reasoning_steps` / `attachments` are informational (safe to auto-burn); **`actions[]`** are vetted
side-effects rootcause *proposes* — render them for a human to click, and they ride back through the
**invocation route**. The gem never auto-runs them.

**Continue the conversation** — the host keeps the history keyed by `session_id`, so a follow-up sends
**only the new message** (never prior turns):

```ruby
RootCause::Embassy.start_analysis(
  subject:    "Still failing after the reset",
  body:       customer_reply,                      # just the new message
  session_id: ticket.rc_session_id,                # the id you persisted above
  metadata:   {resource_type: "SupportTicket", resource_id: ticket.id},
)
```

`session_id` is **opaque** to the gem — store it and forward it, never interpret it. Omit it (or pass
`nil`) on the first turn; the host mints one and returns it in the 202.

## Embedded chat (mint a token, drop in the widget)

Let a signed-in user chat with the rootcause agent from inside your app. Your backend mints a
short-lived, single-use HS256 token; the browser never holds the key, so it cannot chat as another
user, in another tenant, from another origin, or past the expiry.

The chat key is the project's **`webhook_secret`** — a **different** secret from the action
reverse-channel one, and neither falls back to the other. All three settings are optional: an Embassy
without chat behaves exactly as before.

```ruby
# config/initializers/rootcause.rb — extends the block above
RootCause::Embassy.configure do |c|
  c.chat_secret   = ENV.fetch("ROOTCAUSE_CHAT_SECRET")   # the project's webhook_secret
  c.chat_project  = ENV.fetch("ROOTCAUSE_CHAT_PROJECT")  # e.g. "kampadmin-support" (public)
  c.chat_base_url = ENV.fetch("ROOTCAUSE_CHAT_BASE_URL") # e.g. "https://app.replypen.com"
end
```

```erb
<%# app/views/…, with `include RootCause::Embassy::ChatViewHelper` in a helper %>
<%= chat_widget_tag(external_id: current_admin_user.id,
                    kind:        "kampadmin_admin",
                    tenant:      ActsAsTenant.current_tenant.slug,
                    origin:      request.base_url,
                    locale:      I18n.locale,
                    color_scheme: "light",
                    mode:        :page, target: "#rc-chat") %>
```

`external_id` must be an **opaque, stable** user id (never a name/email) — rootcause anchors
conversation ownership to it. `tenant` is the rootcause tenant **slug**, required on tenant-enabled
projects, and must come from your **server-side authorized** tenant context (never client input):
every claim rides inside the signature, so a swapped tenant is simply an invalid token.

`locale` is optional and purely presentational — it sets the chat panel's UI language (`en`, `nl`,
`fr`; a region subtag like `nl-BE` is fine). Anything else falls back to the browser language and then
English. It rides both the claim and `data-rc-locale`, so the panel's server-rendered chrome is in the
right language from the first paint. Omit it to let the browser decide.

`color_scheme` is optional and purely presentational — it pins the chat panel to `light` or `dark`.
Anything else follows the viewer's own light/dark preference. It rides both the claim and
`data-rc-color-scheme`, so the panel paints in the right scheme from the first paint. Set it when your
app is always one scheme (e.g. an always-light admin); omit it to follow the viewer.

Outside Rails (or to mint the token yourself, e.g. for a JSON endpoint that refreshes an expiring
one):

```ruby
RootCause::Embassy.chat_token(external_id: admin.id, kind: "kampadmin_admin",
  tenant: tenant.slug, origin: "https://admin.kampadmin.be", locale: "nl", color_scheme: "light",
  ttl: 900)
# => "eyJhbGciOiJIUzI1NiIs…"  (claims: sub/aud/iss/jti/origin/tenant/locale/color_scheme/iat/nbf/exp/principal — see SPEC.md §5b)
```

`RootCause::Embassy::Chat.widget_tag_html(...)` is the framework-agnostic core behind the view helper
(same options, returns an escaped plain `String`).

## Multi-worker deployments

The default nonce store is an in-process, TTL-pruned set — correct for a **single process**. Across
workers a replay could slip through on a second worker, so inject a shared store (anything responding
to `add?(nonce, ttl:)`, e.g. a `Rails.cache`-backed adapter using `write(unless_exist: true)`):

```ruby
runner = RootCause::Embassy::Runner.new(RootCause::Embassy.config, nonce_store: MyCacheStore.new)
mount RootCause::Embassy::RackApp.new(runner: runner) => "/rootcause/action"
```

The **result route** has its own nonce store with the same caveat — inject a shared one the same way:

```ruby
receiver = RootCause::Embassy::ResultReceiver.new(RootCause::Embassy.config, nonce_store: MyCacheStore.new)
mount RootCause::Embassy::ResultRackApp.new(receiver: receiver) => "/rootcause/result"
```

Likewise, `capture_stdout` swaps the **process-global** `$stdout` for the duration of a run; under a
multi-threaded server that briefly intercepts other threads' output. Set `capture_stdout = false` if
that matters in your deployment.

## Development

```bash
bundle install
bundle exec rake        # standardrb (lint) + rspec
```

# The API plane — call any rootcause endpoint

`RootCause::Embassy.api` is a **generic authenticated caller** for rootcause's HTTP API — the same
surface the `rc` CLI drives. The gem owns transport and auth; the caller owns the path and the body.

There are deliberately **no per-endpoint wrappers**: a new host endpoint is usable from the host app
the day it ships, with no gem release. What the gem promises is narrow and stable — bearer auth
(including the OAuth refresh-token exchange and its cache), timeouts, JSON encode/decode, and a
result struct that never raises for an HTTP outcome.

**What endpoints exist is the host's contract, not the gem's** — see rootcause's API spec / endpoint
manifest (`rc api --help`, or the host's published OpenAPI) for paths, bodies and status codes. Ask the host
repo, not this README.

Implementation: [`lib/rootcause/embassy/api.rb`](../lib/rootcause/embassy/api.rb) (calls) and
[`api_auth.rb`](../lib/rootcause/embassy/api_auth.rb) (bearer + cache).

## Configure (optional — an Embassy that never calls `.api` sets neither)

```ruby
# config/initializers/rootcause.rb — extends the existing block
RootCause::Embassy.configure do |c|
  c.api_base_url = ENV.fetch("ROOTCAUSE_API_BASE_URL") # e.g. "https://app.replypen.com"
  c.api_key      = ENV.fetch("ROOTCAUSE_API_KEY")      # rcor_… machine credential
end
```

Both or neither: setting one without the other raises at boot (a half-wired deployment would
otherwise only fail inside a background job, hours later). Existing Embassies that use only
`start_analysis` / `capture_sent_message` / chat are unaffected.

`api_key` is a **third, separate privilege boundary** — never the action reverse-channel `secret`
(HMAC, no bearer at all) and never `chat_secret`. None of them ever falls back to another.

## Auth (entirely the gem's problem)

rootcause's API takes a short-lived (1h) OAuth **access token** (`rcoa_…`). An Embassy is
provisioned a long-lived, non-rotating **refresh token** (`rcor_…`), which the gem exchanges:

```
POST {api_base_url}/oauth/token          (form-encoded)
  grant_type=refresh_token & refresh_token=<rcor_…> & client_id=rcocl_cli
→ { "access_token": "rcoa_…", "expires_in": 3600 }
```

- The access token is cached **in-process**, per `(api_base_url, api_key)`, behind a mutex — safe
  under multi-threaded Puma/Sidekiq. Each worker process keeps its own.
- It is refreshed **60s before expiry**, so a call that starts just before the boundary never lands
  with a dead token. The clock is monotonic (immune to NTP jumps/suspend).
- A 401 on a token we believed live (host restart, revocation) burns the cache entry and
  re-exchanges **once**; the second answer is final.
- A key that does **not** start with `rcor_` is used **verbatim** as the bearer — a static-bearer
  deployment needs no code change.

## Several projects (refresh tokens are project-pinned)

A rootcause credential is bound to **one project**, so an app that spans several — e.g. Acme
pushing tenant settings to `acme` while editing brains on `acme-support` and
`acme-staff` — holds one credential per project and builds a caller for each:

```ruby
support = RootCause::Embassy.api_for(
  api_base_url: ENV.fetch("ROOTCAUSE_API_BASE_URL"),
  api_key:      ENV.fetch("ROOTCAUSE_SUPPORT_API_KEY"), # a DIFFERENT rcor_ token
)
support.post("/api/v1/brains/acme-support/edit", body: {...})
```

`api_for` returns an **independent** `Api` — the configured `Embassy.api` singleton keeps using
`config.api_key`. Access tokens never mix: the cache is keyed by `(api_base_url, api_key)`, so each
credential exchanges and refreshes on its own. Instances are cheap (build one per call if you like);
the cache lives in `ApiAuth`, not in the instance. Arguments are validated the same way the
`configure` block validates its pair (present key, absolute http(s) URL), and it works before
`.configure` — timeouts and the logger are inherited from the configured Config when there is one.

## Calling

```ruby
RootCause::Embassy.api.get(path, params: nil)
RootCause::Embassy.api.post(path, body: nil, params: nil)
RootCause::Embassy.api.patch(path, body: nil, params: nil)
RootCause::Embassy.api.put(path, body: nil, params: nil)
RootCause::Embassy.api.delete(path, body: nil, params: nil)
```

`path` is joined onto `api_base_url` (an absolute URL is accepted only if it points at that same
origin — a typo must not leak the bearer to another host). `body` is JSON-encoded (pass a String to
send raw bytes); `params` becomes the query string.

## The result — inspected, never rescued

Every outcome comes back as a frozen `RootCause::Embassy::Api::Response`:

| member | meaning |
|---|---|
| `ok?` | the response was 2xx |
| `status` | HTTP status, or `nil` for a transport/auth failure |
| `body` | parsed JSON (Hash/Array) when it parses, else the raw String, `nil` when empty |
| `field_errors` | the host's per-field validation rejections from a 4xx `validation_failed` body |
| `error` | the host's `error`/`message`, or `http_<status>`, or the transport/auth reason |
| `retryable?` | **true** for transport failures, auth failures, 5xx, **429** and **408**; **false** for every other 4xx |

Only a **misconfiguration or a bad argument** raises `ArgumentError` (unset `api_base_url`/`api_key`,
blank path, off-origin URL, unsupported verb) — that is a deploy/caller bug that must reach a
developer, not hide in a result.

Rule of thumb for a job: `retryable?` → raise/re-enqueue and let your retry policy work (the writes
this plane targets are idempotent merges); otherwise log `error` + `field_errors` for ops and stop.

**429 and 408 are retryable**, despite being 4xx: a sweep that pushes every tenant at once will hit
the host's rate limit, and that is backpressure, not a contract break — treating it as permanent
would silently drop those pushes (and page ops for nothing). Every other 4xx is a genuine caller or
validation error, where a retry only burns quota and buries the real signal.

## Worked example — push tenant settings

```ruby
# app/jobs/push_tenant_settings_job.rb
class PushTenantSettingsJob < ApplicationJob
  def perform(tenant)
    result = RootCause::Embassy.api.patch(
      "/api/v1/tenants/#{tenant.rootcause_slug}/profile",
      body: {settings: RootcauseSettingsMapper.new(tenant).to_h, source: "embassy"}
    )
    return if result.ok?

    if result.retryable?
      raise "rootcause settings push failed: #{result.error}" # let the queue retry
    else
      Rails.logger.error("[rootcause] settings rejected: #{result.error} #{result.field_errors}")
    end
  end
end
```

The settings write is a **sparse merge**: only the keys you send are overwritten host-side, so a
re-push of the same keys is a no-op and a retry is always safe. `source` labels the writer in the
host's audit (the host whitelists known sources — `embassy` for this path).

## Logging

The gem logs `[rootcause-api] <VERB> <path> → <status>` on `config.logger`. Never the bearer, never
the body, never the query string (it can carry identifiers).

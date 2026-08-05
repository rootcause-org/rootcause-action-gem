---
name: embassy-action-runner
description: Maintain the rootcause Ruby Embassy's signed action invocation boundary. Use when changing invocation fields, HMAC/replay handling, schema validation, digest resolution, trusted execution context, action script execution, structured results, or host wire-contract compatibility in rootcause-embassy-ruby.
---

# Embassy Action Runner

Read `AGENTS.md` and `SPEC.md` completely before changing behavior. For cross-repo changes, also read
the host's `WIRE-CONTRACT.md` and `.agents/skills/actions/SKILL.md` in `rootcause`.

## Trust path

- Verify HMAC over raw bytes before JSON parsing in `lib/rootcause/action_runner/runner.rb`.
- Replay-guard `issued_at` + `nonce`, then validate host-owned fields and model-influenced params.
- Resolve only a signed, digest-matching `script.rb` through `resolver.rb`.
- Execute through `executor.rb`; params stay frozen data. Trusted tenant context comes only from the
  signed top-level fields and is installed as `RC_TENANT_*` during serialized execution.
- Sign every structured result/refusal over the exact response bytes.

Never derive tenant identity from `params`. A bound signed invocation carries `tenant_id` +
`tenant_slug` and may carry `tenant_scope_value`; a flat invocation omits all three to preserve its
original bytes. Tenant-enabled deployments set `require_tenant_context = true`, which rejects an absent
tuple before resolving the script. The executor removes stale `RC_TENANT_*` first and installs only non-empty trusted
values, so flat/missing scope stays absent. Reserve both tenant field names and `RC_TENANT_*` names from
action schemas. Validate bound ids as non-nil UUIDs, slugs with the host's canonical slug rule, and all
env-bound values as NUL-free before resolving the script.

## File map

- `runner.rb`: authenticated invocation pipeline and trusted host-field validation.
- `schema.rb`: action param contract and reserved tenant selectors.
- `resolver.rb`: signed script fetch + digest verification/cache.
- `executor.rb`: compiled Ruby body, trusted `ENV`, timeout, stdout, structured failure.
- `spec/support/wire.rb`: Ruby-side host fixture builder; keep it aligned with host goldens.
- `spec/runner_spec.rb`: signed end-to-end boundary regressions.

## Verification

Run `bundle exec rake` (StandardRB + all RSpec). For wire changes, cover exact signed success,
tampering, missing/malformed fields, flat context, and param/host separation.

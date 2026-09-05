# Changelog

## 0.9.0

Integrator-visible changes:

- **`dry_run` must be a JSON boolean.** A non-boolean value is now refused with `400 invalid_request`
  *before* the script fetch, instead of being read as truthy. Absent still means "execute".
- **`actions[].resource_url` is validated.** A value that is not an absolute `http(s)` URL is dropped
  from the proposed action; the analysis result is still delivered. `executed_actions[]` never carries
  the field.
- **New config `max_total_attachment_bytes` (default 6 MiB).** `start_analysis` now raises before
  sending when a trigger's decoded attachments exceed the aggregate cap, matching the host's limit.
  The per-attachment `max_attachment_bytes` is unchanged.
- **A malformed API URL raises `ArgumentError`.** `Api#request` previously turned an unparseable URL
  or port into a retryable `Response`, which a background job would retry forever.
- Unexpected-exception log lines carry the exception class only, never its message text.

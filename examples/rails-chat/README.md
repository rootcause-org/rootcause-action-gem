# Rails chat example

This minimal slice keeps identity minting on the authenticated Rails backend and mounts the page-mode
widget into `#replypen-chat`.

Copy the files into an existing Rails app, then set:

```text
ROOTCAUSE_CHAT_SECRET=<operator-provided chat signing secret>
ROOTCAUSE_CHAT_PROJECT=<public project slug>
ROOTCAUSE_CHAT_ORIGINS=https://your-app.example
```

The example assumes `current_user`, optional `current_tenant`, and your normal authentication guard.
Adapt those names to the app; never accept the external id or tenant from request parameters.

Allow the hosted origin in CSP:

```text
script-src 'self' https://app.replypen.com
frame-src https://app.replypen.com
connect-src 'self' https://app.replypen.com
```

The authenticated `token` POST validates the browser origin against `ROOTCAUSE_CHAT_ORIGINS`, rate
limits each principal through the shared Rails cache, and sets `Cache-Control: no-store`. The browser
remounts a fresh loader at the two-hour token's half-life; the loader's guarded full-page reload is the
fallback if a token expires first. This JavaScript path is used instead of `chat_widget_tag` so a
long-lived page can rotate and remount without a full render.

Complete setup and verification guidance:
[`docs/integrator/`](https://github.com/rootcause-org/rootcause-embassy/tree/main/docs/integrator).

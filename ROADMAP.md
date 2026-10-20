# OutboundWin — Roadmap (out-of-scope / future work)

Items deliberately deferred from this build (see SPEC "Out of scope"), plus natural next steps.
None are blockers for the shipped app; each is gated on explicit user approval where noted.

## v2 / later (SPEC out-of-scope)
- **Kernel / WFP callout driver** — real "hold the connection while I ask" behavior in Ask mode.
  Requires a driver, signed + installed → the v1 app can only observe-then-prompt. Needs kernal signing cert & explicit approval.
- **Licensing / payments** — activation keys, trial handling, license server.
- **MDM / managed rule feed** — push rules from a central admin console to fleet machines.
- **Built-in AI chat / Analytics overview** — an in-app assistant; today the MCP server exposes
  read-only tools so external agents can drive it.
- **ACP agent integration** — first-class agent-control-plane hooks beyond the named-pipe protocol.
- **Widgets / share cards / badges** — OS-level widgets and shareable connection "cards".

## v1.5 (natural extension, no gating)
- **Firewall enforcement real apply** — `outboundctl enforce --apply` currently stubbed pending the
  user's explicit go-ahead (SPEC §0.5; dry-run is the default by design).
- **DoH resolution** — Chrome/Edge built-in resolver encrypts DNS on :443, so those flows show the
  IP until a plain-DNS event for the same IP back-fills the name. Consider DoH/ECH-aware hooks.
- **Toast preferences** — per-event-type toggle (blocked vs new-country) and a quiet-hours window.
- **Blocklist catalog browsing** — a picker of well-known community lists inside Settings rather than
  URL-entry only.
- **Labs floating globe** — the always-on-top resizable globe window is optional; not yet built.

## Notes
- All toasts are rate-limited to ≤1 per 8 s (SPEC Phase 5).
- SMB Security Pack / LiveDub / OutboundWin products are separate concerns; nothing here crosses into them.
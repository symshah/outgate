# OutboundWin — Parity spec (Phases 6–9)

Goal: OutGate must match the reference design for layout, spacing and look. SPEC.md Phases 0–5 built the engine. This file covers what is still missing or broken. Read it together with SPEC.md and PROGRESS.md. Work through it in order.

---

## THE MOST IMPORTANT RULE: test the way the user uses it

Everything so far "passed" with test flags (`--page`, scripted pushes, self-tests), but when the user opened the app normally, the map and pages did not work. From now on, an item is DONE only when:

1. All `Outbound.exe` processes are closed.
2. The app is started **exactly like the user does**: double-click / `Start-Process` on `G:\OutboundWin\src\Outbound.App\bin\Debug\net8.0-windows\Outbound.exe`, elevated, **no command-line flags**.
3. A screenshot of the feature working is saved to `G:\OutboundWin\screens\<item>.png` and linked in PROGRESS.md.
4. It looks comparable to the matching reference screenshot (below).

Test hooks may be used for debugging, never as proof.

### Reference screenshots
Reference screenshots for the original design were kept locally in `reference/` during development and are not distributed with this repository.

Windows look: same layout and spirit, Fluent controls (WPF-UI), Mica, light + dark. Don't fake macOS window chrome.

---

## Phase 6 — Make what exists actually work (FIRST)

Launch as the user does, then fix in this order:
1. **Map page.** Find out why it fails on a normal launch (web assets not copied next to the exe, WebView2 user-data folder locked by an earlier non-elevated run, map only initialised via `--page map`, no data push on a normal start). Show a clear message on the page if WebView2 fails, never a blank page.
2. **Menu navigation** with real mouse clicks on every page.
3. **Activity** fills with live rows within a few seconds of launch.
4. **Status bar / Overview** show real numbers.
5. **Tray icon + flyout** open and work.
6. Remove the stray "SMB Security Pack / LiveDub" note from ROADMAP.md.
7. Clean the rule store of test rules from development sessions (list them in PROGRESS.md first).

Save a screenshot of every page.

---

## Phase 7 — Real enforcement (user must be present; ask before the first apply)

1. Back up first: `netsh advfirewall export G:\OutboundWin\backup\fw-<date>.wfw`.
2. Every Windows Firewall rule the app creates uses group name **OutboundWin**.
3. `outboundctl enforce --apply`, `--remove-all` (removes only OutboundWin-group rules), and the app applies rule changes automatically when enforcement is ON.
4. Settings switch: Enforcement ON/OFF (default OFF until the user turns it on).
5. "Network not working?" → Pause 15 min / Turn off = remove-all, and restore when resumed.
6. Never change the firewall default outbound policy. Strict mode = explicit block rules for apps without a rule.
7. Acceptance with the user: deny rule blocks `curl https://example.com`; explain names it; one click in "Network not working?" unblocks it; DNS/DHCP keep working; remove-all restores everything.

---

## Phase 8 — Feature parity (one item at a time)

### Ask prompt (alert)
- Queue: all waiting apps listed at the side; "answer all for this app".
- Says when the server belongs to the app's own publisher (same registrable domain / publisher name), otherwise shows "Outbound doesn't recognise this server".
- Timeouts: unanswered = allowed after 8 s (UDP) / 60 s (TCP), configurable 15–120 s for TCP, option "block when unanswered"; unanswered items go to Review.
- Optional sound when a prompt appears; Narrator reads the prompt (UIA name/help text set).

### Rules
- Match an app by **publisher + exe name** (signed apps) or by **exact path**. A changed binary (hash/signature) is treated as new.
- Direction field, priority flag, profile tag, source tag, on/off switch per rule (as in rules-light reference).
- Export / import rules to a file; keep the previous store as a backup on import.
- Profiles: switch from the UI and with `outboundctl profile list|use <name>`.

### Network monitor (Activity)
- Columns: app, destinations, Sent, Received, Last seen, allowed/blocked counts, allow/block switch.
- Live traffic bar per app.
- **Traffic chart**: upload above the centre line in orange, download below in blue, each half on its own scale; hover shows time + rates; drag selects a time window that filters BOTH the list and the map.
- Map shown beside the list (above it when the window is narrow).
- **Scoped search**: `app:`, `host:`, `port:`, `proto:`, `country:`, `direction:`, `rule:` with quoted values (`app:"Google Chrome"`), plus a menu in the search box that inserts them. Keep the smart-filter tokens.
- **Inspector**: names the rule that decided the selected connection (or "no rule — <mode> decided"), and lets the user change the decision right there. Daily data limit set here; notify at 80 % and 100 %, optional block until midnight.
- Real icons for apps, Windows services, command-line tools, and website favicons (favicons fetched directly from the site, switchable off in Settings).

### Trusted Windows components
- Microsoft-signed binaries in Windows system folders are trusted from the start (no alert storm). A Microsoft binary copied elsewhere is still asked about.

### Tray flyout
- Status, mode switch, today's numbers, latest connections, recent blocks each with an **Allow** button, live up/down rate, optional mini map or globe.

### Modes
- Learn: after a few days, suggest reviewing and switching to Ask.
- Review: **Allow Verified Publishers** in one step.

### Blocklists
- Hosts, domain and CIDR formats, up to 200,000 entries per list, failed fetch keeps the last good list.

### Help
- **Network not working?** also lists other network filters / VPN adapters Windows reports.
- **Report a problem**: description + optional diagnostics with no sites, addresses or app names; preview exactly what's included; save to a file (no automatic sending).

### First-run setup
- Short wizard: explains admin rights, checks ETW works, offers to download the offline GeoIP database, picks a mode, and ends on a live world map drawing the first connections as they happen (see onboarding reference).

---

## Phase 9 — Map, globe, Labs, Highlights, Intelligence

### Map & globe
- 2D and 3D in the monitor, map styles **Standard, Muted, Satellite** (Satellite from a bundled public-domain Blue Marble image, fully offline).
- Connection pop-ups spring in; packets glide along great-circle arcs; blocked in red.
- Globe themes: Graphite, Blue Marble, Midnight, Daylight, Amber.

### Labs (Settings › Labs), each with its own on/off switch and a cost label
- **Floating globe**: always-on-top, resizable, movable window with themes and app icons at destinations.
- **Live world in the tray flyout**: small map with a thread to each place reached in the last few seconds.
- **New-country capsule** (Windows version of the notch island): a small capsule at the top of the screen "App → Country, first time today", folds away; at most once every 8 s.
- **Taskbar globe**: while the window is open, the taskbar thumbnail/icon overlay shows today's routes.
- Presets **Efficient / Balanced / Showcase**, each switch showing its cost (Light / Uses more).

### Highlights
- Privacy score with daily streak, awards, **network passport** (countries reached), Year in Review. Share cards previewed and saved as an image; nothing shared automatically.

### Analytics & AI
- Analytics page with a short written overview and an **AI Agents** section (which AI apps connect, which AI services, which countries).
- Assistant with **your own API key or a local OpenAI-compatible server** (LM Studio / Ollama): plain-language questions about the network; answers show the records used (chart/timeline/map/cards).
- Every number in an answer is checked against Outbound's own figures; mismatches are replaced with Outbound's summary.
- Privacy: nothing is sent until the user turns it on; "Show what's sent…" previews the exact request; never send addresses, full host names, file paths or rules to a cloud model. Key stored with Windows Credential Manager (DPAPI).
- `outboundctl ai ask "<question>"`.
- Settings › Intelligence: "Add Outbound to" buttons that write the MCP config for Claude Desktop, Cursor and VS Code; switch to make AI apps read-only.

---

## Still out of scope
- Holding a connection open while asking (needs a WFP callout driver), licensing/payments, MDM/managed rule feed, ACP coding-agent integration. Keep these in ROADMAP.md.

## Working rules (unchanged)
- Build first, fix only what the compiler reports. Max 3 build-fix cycles, then BLOCKED and move on.
- UI checks: launch as the user, screenshot as proof. UIA patterns for automation; no synthetic mouse clicks.
- PROGRESS.md report + Telegram line after each phase. Next item into PROGRESS.md before the tool-call limit.
- No drivers, no reboot, no GPL dependencies, never change the firewall default policy.

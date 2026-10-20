# OutboundWin — build spec for Hermes

You are continuing work on **OutGate** (internal project name: OutboundWin), a Windows outbound firewall monitor. The existing solution is at `G:\OutboundWin` (projects: Outbound.Core, Outbound.App (WPF), outboundctl (CLI), outbound-mcp (MCP server), Outbound.Tests). .NET SDK is at `G:\tools\dotnet`. Extend this code — do not start a new solution.

Save this file as `G:\OutboundWin\SPEC.md` and re-read it at the start of every phase.

---

## 0. Ground rules (read first)

1. Work **one phase at a time**. At the end of each phase: build green, tests green, live check done, then send me a short report (what works, what doesn't, evidence) and **wait for my OK** before the next phase.
2. "Verified" means you show real output. Live data must be checked against ground truth: `netstat -ano`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, Resource Monitor. Never write "verified empirically" without pasting the comparison.
3. Never conclude "the data is not available" from one failed probe. Re-check the API docs (iphlpapi.h / learn.microsoft.com) first.
4. Never delete a feature or a test to make a build pass.
5. Enforcement runs in **dry-run** by default during development. Ask me before: changing the Windows Firewall default outbound policy, installing any driver, anything needing a reboot, or adding a dependency with a GPL licence.
6. Keep the whole thing local. No telemetry, no cloud calls except blocklist fetches I add.

---

## Phase 0 — Fix the connection collector (blocking bug)

The current IP Helper structs and table class are wrong, which is why PIDs/IPs/states were garbage and why UDP "had no PID". Correct definitions per iphlpapi.h — **every field is a DWORD**, ports are DWORDs with the port in the low 16 bits in network byte order:

```csharp
// GetExtendedTcpTable(..., AF_INET=2, TCP_TABLE_OWNER_PID_ALL=5, 0)
[StructLayout(LayoutKind.Sequential)]
struct MIB_TCPROW_OWNER_PID {          // 24 bytes
    public uint State;                 // MIB_TCP_STATE 1..12
    public uint LocalAddr;             // network byte order
    public uint LocalPort;             // low 16 bits, network order
    public uint RemoteAddr;
    public uint RemotePort;
    public uint OwningPid;
}

// GetExtendedUdpTable(..., AF_INET=2, UDP_TABLE_OWNER_PID=1, 0)
// NOTE: table class 0 = UDP_TABLE_BASIC, which has NO PID (8-byte rows).
// That is what the earlier probe used by mistake.
[StructLayout(LayoutKind.Sequential)]
struct MIB_UDPROW_OWNER_PID {          // 12 bytes
    public uint LocalAddr;
    public uint LocalPort;             // low 16 bits, network order
    public uint OwningPid;
}
```

Also add IPv6 (`AF_INET6=23`, `MIB_TCP6ROW_OWNER_PID` / `MIB_UDP6ROW_OWNER_PID`). Port conversion: `(ushort)IPAddress.NetworkToHostOrder((short)(port & 0xFFFF))`. Row pointer: `buf + 4 + i * Marshal.SizeOf<T>()`; assert the sizes (24 / 12) in a unit test.

**Done when:** a side-by-side dump of 20 TCP and 20 UDP rows matches `netstat -ano` exactly (address, port, state, PID).

---

## Phase 1 — Data pipeline

UDP rows have no remote endpoint and the IP Helper tables have no hostnames or byte counts, so the real pipeline uses ETW:

- **Connections + bytes:** ETW provider `Microsoft-Windows-Kernel-Network` (TCP/UDP connect, send, recv with PID, remote IP/port, size) via `Microsoft.Diagnostics.Tracing.TraceEvent`. Keep the IP Helper snapshot as a fallback/reconciler.
- **Hostnames:** ETW `Microsoft-Windows-DNS-Client` (query name + returned IPs + PID). Map remote IP → hostname per process. Show the hostname when the app connected by name, otherwise the IP.
- **Registrable domain** ("main domain", shown in bold): Public Suffix List, bundled offline.
- **App identity / helper folding:** group processes into one app row: same executable path / parent chain (chrome.exe renderers → Google Chrome), UWP/MSIX by package family name, `svchost.exe` split by hosted service name. Show "N processes" with an expandable list.
- **Signer:** WinVerifyTrust, **including catalog-signed files** (CryptCATAdmin*), so Windows binaries show "Microsoft Windows" not "unsigned". Three states: Microsoft, named publisher, unsigned. Real exe icon extracted for each app.
- **Location:** offline GeoIP (DB-IP Lite City mmdb, CC BY 4.0) read with `MaxMind.Db`. No online lookups.
- **Storage:** SQLite (existing store) — connections, per-destination bytes sent/received, allowed/blocked counts, first/last seen. Traffic sampled every 5 s for sparklines.

**Done when:** opening `https://example.com` in Chrome produces a row: Google Chrome · Google LLC · example.com · 443 TCP · country/city · bytes · last seen, and the numbers are in the same ballpark as Resource Monitor's Network tab.

---

## Phase 2 — Rules, modes, enforcement

**Rule model** (rules read as sentences, e.g. "Deny connections to telemetry.zoom.us on any port for Zoom"):
- App: specific app or Any app
- Destination: host, domain (covers subdomains), IP, CIDR, Local network, Any
- Port(s) + protocol (TCP/UDP/Any); direction field (outbound for now)
- Action: Allow / Deny; **Priority** flag (priority rules win; otherwise deny wins at equal specificity, most specific wins otherwise — keep the existing tested logic)
- Lifetime — six options: **Once, 1 Hour, Until Quit, Until Logout, Until Restart, Forever** (Until Logout = session ID, Until Restart = boot ID)
- Source tag: user / blocklist / profile / AI-requested / imported
- Profile (see Phase 5)

**Modes** (switchable from the tray):
- **Learn** — allow everything new quietly, record it in Review. Never re-trust an app whose binary hash/signature changed; treat it as new.
- **Ask** — prompt for anything new.
- **Strict** — block anything without a rule, record it in Review.

**Unanswered prompts:** allow after 8 s (UDP) / 60 s (TCP) by default, configurable 15–120 s for TCP, or "block when unanswered"; either way it goes to Review.

**Enforcement on Windows:** keep the current FirewallEnforcer approach for v1 (domain rules resolved to IPs from the DNS mapping and refreshed as new IPs are seen). Windows can't hold a connection open while you ask without a kernel callout driver, so in Ask mode v1 behaves as: the first connection is observed, the prompt appears, the answer becomes a rule for subsequent connections (option: "block new apps until answered" so the app's retry succeeds once allowed). A WFP callout driver is **out of scope** — note it as a v2 item, don't attempt it.

Safety: always-allow DNS, DHCP, NTP and core Windows networking so Strict mode can't brick the PC. Import keeps a backup of the previous rule store.

**Done when:** a deny rule for `example.com` for `curl.exe` blocks `curl https://example.com` (with dry-run off, after I approve), `outboundctl explain` names the deciding rule, and all six lifetimes expire correctly in tests.

---

## Phase 3 — UI (WPF, Fluent look)

Look: clean, light, lots of white space, rounded app-icon tiles, soft cards, light background `#FAFBFC`, full dark mode. Use **WPF-UI (lepoco/wpfui)** for Fluent controls + Mica, **H.NotifyIcon** for the tray, ScottPlot or LiveCharts2 for sparklines. Use my own Outbound icon/assets.

**Tray icon + flyout panel** (the everyday surface):
- Status line ("Outbound is on · Checking every connection"), Learn/Ask/Strict segmented switch
- Counts: apps, allowed, blocked; live up/down rate next to the tray icon tooltip
- Recent list: app icon · host · ✓/✕
- "Open Outbound" button; Pause 15 min; Turn off

**Connection prompt (the "question" window):**
- App real icon, name, "Signed by <publisher>" (or Unsigned, highlighted)
- Destination with registrable domain in bold so look-alikes stand out; port · protocol · service name (443 TCP HTTPS)
- Note when the host belongs to the app's own publisher vs. unrecognised
- Lifetime picker: Once / 1 Hour / Until Quit / Forever (+ Logout/Restart under "More")
- Scope: this port only / any port / any port and protocol
- Countdown showing what happens on timeout
- Deny / Allow — **buttons enable only after ~1 s** so a stray keystroke can't decide
- Side queue of other waiting apps; "answer all for this app"

**Main window** — left navigation:
1. **Overview** — protection status, filter health, apps online, allowed/blocked today, most active apps, recently blocked hosts.
2. **Activity** — apps grouped with their destinations. App row: icon, name, N destinations, signer, last-hour sparkline, allowed/blocked counts, last seen, allow/block toggle. Expanded destination row: host (main domain bold), port·proto, flag + city, bytes, last seen. Right-hand **inspector** explaining *why* a connection was allowed/blocked (deciding rule). Search box with **smart filter tokens**: AI apps, ad/tracking hosts, new apps, unsigned apps, Microsoft services, local network, abroad, heavy users. Time-range picker.
3. **Rules** — grouped by app, written as sentences, with lifetime, profile, source tags, match counts today; add/edit/disable/delete; Priority toggle.
4. **Review** — things decided without asking, grouped by app, newest first; allow/block per item → becomes a rule; dismiss; "Allow verified publishers" bulk action.
5. **Map** — see Phase 4.
6. **Settings** — General (mode, timeouts), Blocklists, Profiles, Intelligence (MCP), Privacy, Labs.

**Help → Network not working?** — shows current state, Pause 15 min, Turn off, and blocks from the last 30 minutes with one-click Allow.

---

## Phase 4 — Map and globe

Host a local page in **WebView2**, fully offline (bundle everything, no CDN/tiles):
- 2D map: d3-geo + world-atlas TopoJSON; arcs from this PC to each city reached, blocked in red, list of top places beside it. Dragging across the traffic chart filters both map and list to that time window.
- 3D globe: globe.gl (bundled), great-circle arcs, app icons at destinations.
- Themes: Graphite, Blue Marble, Midnight, Daylight, Amber.
- Optional (Labs): always-on-top floating globe window, resizable, movable.

---

## Phase 5 — CLI, MCP and extras

- **outboundctl:** `status`, `mode get|set`, `rules list|count|add|remove|enable|disable`, `explain --app <exe> --host <h> --port <n>` (prints Decision, Decided by rule ID, matching rules), `export --jsonl`, `mcp`. Talks to the running app over a named pipe.
- **MCP server:** read tools for apps, hosts, countries, blocked, rules (same figures as the UI, never connection contents). Rule-change tools create a **pending request** that shows an approval dialog in the app ("<client> wants to change a rule", the rule as a sentence, the client's reason, Don't Allow / Allow). Setting to make MCP read-only.
- **Profiles:** e.g. Home / Office, offered when joining a new network (Network List Manager events).
- **Blocklists:** subscribe over HTTPS (hosts format / domain lists), up to ~200k entries, memory-efficient (domain trie), a failed fetch keeps the last good list.
- **Daily data limit per app:** set in the inspector; notify at 80 % and 100 %, optional block until midnight.
- **Toast notifications** for blocked connections / first connection to a new country (rate-limited, ≤1 per 8 s).
- **Audit export:** JSON Lines.

---

## Out of scope for this build
Kernel/WFP callout driver, licensing/payments, MDM/managed rule feed, built-in AI chat/Analytics overview, ACP agent integration, widgets, share cards/badges. List them in `ROADMAP.md`.

## Final acceptance test (I'll run this with you)
1. 20 TCP + 20 UDP rows match `netstat -ano`.
2. Chrome → example.com shows correct app, signer, host, country, bytes.
3. A renamed copy of curl.exe triggers the Ask prompt; Allow/Forever creates a sentence rule; second run is silent.
4. Deny rule blocks curl; `outboundctl explain` names it; "Network not working?" can unblock it in one click.
5. Strict mode leaves DNS/DHCP working.
6. An MCP client's rule change waits for my approval.

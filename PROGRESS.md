# OutboundWin — progress log

## Status: ALL Phases 0-5 DONE. 3 bugs fixed + toasts + audit export confirmed. No BLOCKED items. Final summary below.

## 2026-10-15 — IPC pipe-ownership regression (admin launch) FIXED

**Symptom:** `outboundctl` failed with "Could not connect to the pipe because it was not owned by the
current user" when `Outbound.exe` was started as admin. Worked in Phase 5.

**Root cause:** `.NET bug dotnet/runtime#123903` — the *client*-side `PipeOptions.CurrentUserOnly`
derives the allowed SID from the **server process's Owner** (who launched it), not its User SID.
Launch the app elevated and the owner can become `Administrators`/`SYSTEM`, so the user's own
token fails the check. (Check #1 was fine: `CreatePipeSecurity()` → `sec.SetOwner(user SID)` **is**
passed to `NamedPipeServerStreamAcl.Create` on every instance, incl. the multi-instance loop.)

**Fix:**
1. `outboundctl` client: `PipeOptions.CurrentUserOnly` → `PipeOptions.None`. The server DACL
   (Allow current-user SID FullControl + Deny NETWORK S-1-5-2 + default-deny) is now the sole
   authoritative control — grants the user's RID in both elevated and normal tokens, still blocks
   other local users and SMB. Elevation-independent.
2. `IpcServer.LogPipeIdentity()`: at pipe startup, writes to `engine.log` the `ownerSID`,
   `launchOwnerSID`, `user`, `elevated`, plus a **WARNING if running as SYSTEM** (check #3) and
   an elevation note. Makes any owner/user mismatch diagnosable without a debugger.

**Verified:** build green (0E), 129/129 tests. Live: app started **elevated** (engine.log shows
`elevated=True`, `ownerSID=S-1-5-21-…-1000`) → `outboundctl status` returns
`mode=Learn dry-run=true flows=… rules=7`. Re-test from both normal + admin PowerShell.

## 2026-10-12 — Bug-fix round + toasts + audit export + ROADMAP (FINAL)

### BLOCKED: none
No item hit the 3-cycle build limit. Build is green (0E/4W) and the full suite passes.

### Fixed (build green, 129/129 tests, all live-verified over the pipe)
1. **NormalizeAppKey bare-name bug.** Bare app names no longer map to `C:\Windows\System32\<name>`.
   `AppResolver.NormalizeAppKey(app, knownExePaths)` now resolves bare names against the apps the
   engine has seen (exe file-name match, case-insensitive, extension optional). 1 match → its full
   path; several → clear error listing paths; none → clear error. UI + IPC both pass the engine's
   seen exe paths. **Verified live:** `limits set chrome.exe` → the real running Chrome path
   (not System32); a bogus name → `no running app matches '…' — pass the full exe path`.
2. **rules.propose field mismatch.** Server returned `applied=false` on denial but clients read
   `approved`. Server now returns `approved` (true/false) in both branches; `outboundctl` and
   `outbound-mcp` both read `approved`. No legacy `applied` remains.
3. **Unknown --lifetime rejected.** New `Rule.ParseLifetime(s)` (Core, shared by the IPC server's
   ParseRule) rejects unknown tokens with `unknown lifetime '<x>' - valid values: once, 1h, quit,
   logout, restart, forever` — never silently Forever. Covers CLI + MCP + IPC.
   **Verified live:** `rules add --lifetime friday` → error; `rules count` unchanged at 6.

### Toasts (SPEC Phase 5) — NEW
- `Policy/ToastService.cs` (pure, testable): blocked-connection and first-to-new-country toasts,
  **rate-limited to ≤1 per 8 s**. Hooked in `PolicyService.OnFlow`; MainWindow marshals the event
  to the UI thread and shows a tray balloon via `TaskbarIcon.ShowNotification`.
- 5 toast tests. **129/129 total green.**

### Audit export — CONFIRMED live
`outboundctl export --jsonl` → JSON Lines, one rule per line, from the running app:
`{"id":1,"action":"Deny","app":"C:\\Windows\\System32\\curl.exe","destination":"example.com",…}`.

### Docs
- `ROADMAP.md` written: kernel/WFP driver, licensing, MDM feed, AI chat, ACP, widgets, real
  firewall enforce (needs user OK), DoH resolution, toast prefs, blocklist catalog, Labs globe.

### Verified live this round
- Stale dev Outbound (PID 3416) killed to unlock the build; relaunched for pipe tests.
- status / export / limits set+clear / lifetime rejection all exercised over the named pipe.

## Phase 0 — connection collector fix (DONE)

### What was wrong
1. `GetExtendedTcpTable` / `GetExtendedUdpTable` were called with **table class 0** (basic tables): no PID, and for TCP only listeners. That produced the garbage PIDs/IPs/states and the false "UDP has no PID" conclusion.
2. The IPv6 row structs I first wrote were guessed from memory — wrong field order and missing `dwLocalScopeId`/`dwRemoteScopeId`. Caught by the full multiset comparison (IPv4 matched, every IPv6 row was off). Fixed against the official tcpmib.h definitions:
   - `MIB_TCP6ROW_OWNER_PID` = **56 bytes**: LocalAddr[16], dwLocalScopeId, dwLocalPort, RemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid (state and PID come LAST).
   - `MIB_UDP6ROW_OWNER_PID` = **28 bytes**: LocalAddr[16], dwLocalScopeId, dwLocalPort, dwOwningPid.
3. My `TcpState` enum had wrong values (I wrote Established=1; the real MIB_TCP_STATE_ESTAB is **5**). Fixed per learn.microsoft.com tcpmib: CLOSED=1, LISTEN=2, SYN_SENT=3, SYN_RCVD=4, ESTAB=5, FIN_WAIT1=6, FIN_WAIT2=7, CLOSE_WAIT=8, CLOSING=9, LAST_ACK=10, TIME_WAIT=11, DELETE_TCB=12.

### What the code now uses (per SPEC.md Phase 0 + iphlpapi.h)
- TCP: `GetExtendedTcpTable(..., AF_INET=2, tableClass=5 /*TCP_TABLE_OWNER_PID_ALL*/, 0)`; row = `MIB_TCPROW_OWNER_PID`, **24 bytes**, all DWORDs: State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid.
- UDP: `GetExtendedUdpTable(..., AF_INET=2, tableClass=1 /*UDP_TABLE_OWNER_PID*/, 0)`; row = `MIB_UDPROW_OWNER_PID`, **12 bytes**: LocalAddr, LocalPort, OwningPid.
- IPv6: same calls with `AF_INET6=23` and the 56/28-byte structs above; link-local addresses rendered netstat-style (`fe80::…%ifIndex`).
- Ports: `(ushort)IPAddress.NetworkToHostOrder((short)(port & 0xFFFF))`.

### Unit tests (46 total, all green)
`Marshal.SizeOf` assertions: TCP row = **24**, UDP row = **12** (plus IPv6 rows = 56 / 28), port-DWORD conversion theory cases, and a guard asserting every `TcpState` value matches iphlpapi.

### Live check vs netstat -ano (full multiset comparison, same instant)
```
TCP: outboundctl=188 netstat=188 exact-match-rows=188 only-in-ctl=0 only-in-netstat=0
UDP: outboundctl=99  netstat=99  exact-match-rows=99  only-in-ctl=0 only-in-netstat=0
```
Every row matches on local address, local port, remote address, remote port, state and PID — including all states (LISTENING/ESTABLISHED/TIME_WAIT/FIN_WAIT_1/CLOSING) and IPv6 rows.

Sample side-by-side (20 TCP rows, first run of the corrected build):
```
OK   ctl=0.0.0.0:135->0.0.0.0:0 LISTENING pid=2304 | netstat=0.0.0.0:135->0.0.0.0:0 LISTENING pid=2304
OK   ctl=0.0.0.0:445->0.0.0.0:0 LISTENING pid=4    | netstat=0.0.0.0:445->0.0.0.0:0 LISTENING pid=4
OK   ctl=0.0.0.0:2179->0.0.0.0:0 LISTENING pid=3340 | netstat=0.0.0.0:2179->0.0.0.0:0 LISTENING pid=3340
OK   ctl=0.0.0.0:5432->0.0.0.0:0 LISTENING pid=7144 | netstat=0.0.0.0:5432->0.0.0.0:0 LISTENING pid=7144
... (all 20 OK)
```

### Notes / known limitations
- UDP socket table has no remote endpoint by design — rows show local only (same as netstat).
- MIB rows carry no byte counters; per-flow volume comes from ETW in Phase 1.
- Transient connections between two separate snapshots can differ by a few rows; the multiset check above ran both reads back-to-back and matched exactly.

---

## Takeover cleanup + code review (2026-10-12)

**Cleanup:** deleted `scratch-etw/` (EtwProbe, EtwRealtimeTest/FinalProbe.cs, probe7, dns_reader.ps1, outputs), `G:\tmp\etwsrc.cs`, and 6 stray `tcp_probe*/udp_probe*` scripts in the Hermes scratch dir. The Phase-0 comparison scripts were kept in `tools/`. `logman query -ets` showed **no** `Outbound*` sessions (one unnamed `TraceEventSession` with provider {151F55DC…} does not come from any OutboundWin probe and was left alone). `EtwNetworkCollector.StopStaleSessions()` now cleans `Outbound*` sessions on every start.

**Review fixes (clearly wrong, now fixed):**
| Where | Bug | Fix |
|---|---|---|
| `ProcessIdentity` | WinVerifyTrust P/Invoke had 4 params (real signature is `(HWND, GUID*, LPVOID)`), `WINTRUST_DATA` lacked `cbStruct`, no catalog support → everything "unsigned"/crash risk | New `Identity/Signer.cs` per wintrust.h, catalog first then embedded; `ProcessIdentity` is now a facade over it |
| `outboundctl` | arg loops ran to `args.Length - 1`, so a trailing flag (`--json`, `--deny`) was silently ignored | loop to `args.Length` |
| `outbound-mcp` | wrote an empty line in reply to JSON-RPC notifications | notifications get no output |
| `FlowMonitor` | flow key `proto:remoteIp:port` merged different processes/sockets (all listeners collapsed into one) | key includes pid + local endpoint |
| `FirewallEnforcer` | default `dryRun=false` (SPEC §0.5 says dry-run by default); hostname rules emitted `remoteip=example.com` (invalid in netsh) | default `true`; hostnames use the resolved IPs, skipped when none |
| Rule lifetimes | `Once`, `UntilLogout`, `UntilRestart` never expire | tracked for Phase 2 (below) |

## Phase 1 — data pipeline (DONE)

**Architecture** (`Outbound.Core`):
- `Etw/EtwNetworkCollector` — session `OutboundWin-Net`: `EnableKernelProvider(NetworkTCPIP | Process)` → TcpIp/UdpIp Send/Recv/Connect (+IPv6) with PID, size, daddr/saddr/dport/sport (fields per learn.microsoft.com *TcpIp_TypeGroup1 / UdpIp_TypeGroup1*), plus Process/Start+DCStart for the image path (short-lived processes such as curl exit before we could open them). Session `OutboundWin-Dns`: `Microsoft-Windows-DNS-Client {1c95126e-7eea-49a9-a3fe-a378b03ddb4d}` event **3008** (local manifest: "DNS query is completed for the name %1, type %2, query options %3 with status %4 Results %5") → QueryName + QueryResults, and the in-box `Microsoft-Windows-NDIS-PacketCapture` provider (receive path only) to parse DNS **responses** on the wire.
- `Pipeline/DnsMap` (per-PID name first, then global), `Pipeline/DnsWire` (DNS response parser), `Domains/PublicSuffixList` (bundled `assets/psl/psl.dat`, 10,336 rules), `Geo/GeoIp` (DB-IP Lite City mmdb, CC BY 4.0, `MaxMind.Db` Apache-2.0, offline), `Identity/AppResolver` (package family → svchost services → parent-chain folding by same exe / same ProductName+CompanyName), `Store/TrafficStore` (tables `apps`, `destinations`, `samples` every 5 s, `connections`), `Engine/OutboundEngine` (wires it all; IP Helper snapshot reconciles every 5 s).
- Non-elevated fallback: IP Helper snapshot + `Get-DnsClientCache`.
- `outboundctl watch [--seconds N] [--host s] [--exe x] [--json] [--no-etw]` and `outboundctl signer <files>`.

**Findings worth keeping:**
1. **UDP Recv uses literal packet semantics** (`daddr` = this PC); TCP Recv reports `daddr` = remote peer. Before the fix, Chrome's DNS replies showed as `192.168.31.2:<ephemeral>` and QUIC showed recv=0. After: `192.168.31.1:53 UDP sent 442 recv 1121`, QUIC `sent 4216 recv 7060`.
2. **Chrome uses its own built-in DNS resolver**, so DNS-Client 3008 never fires for it (all Chrome rows had no hostname). Fixed by parsing DNS responses from NDIS-PacketCapture → global map; hostnames get back-filled when the DNS event is read after the packets.
3. Catalog lookup has to come **first**: in-box binaries carry both signatures and Windows reports the catalog signer.

**Evidence: curl → https://example.com (final run, after all fixes)**
```
=== ground truth (curl)
curl_pid=29688
remote_ip=104.20.23.154 remote_port=443 size_request=75 size_upload=0 size_header=347 size_download=577 http=200
=== outboundctl watch
source=etw geo=True psl=10336
DNS3008 pid=29688 name=example.com status=0 ips=104.20.23.154,172.66.147.243
  PID APP                  SIGNER            HOST         REMOTE          PORT PR  GEO        SENT RECV
29688 The curl executable  Microsoft Windows example.com  104.20.23.154    443 TCP CA Toronto  659 5810
leftover Outbound* ETW sessions after exit: (none)
```
PID, IP and port match exactly. RECV 5810 = 924 bytes of HTTP plus the TLS handshake (certificate chain).

**Bytes accuracy (5 MB download):** curl `size_download=5000000 size_header=1309`, so 5,001,309 app bytes; ETW recv **5,012,932** (+0.23%, TLS record overhead). Row: `curl · Microsoft Windows · speed.cloudflare.com · 162.159.140.220:443 TCP · CA Toronto`.

**Chrome (headless, fresh profile) → example.com:**
```
2472 Google Chrome  Google LLC  example.com                    172.66.147.243  443 UDP CA Toronto        4216 7060
2472 Google Chrome  Google LLC  clientservices.googleapis.com  142.250.187.78  443 TCP US Mountain View 2027 6759
2472 Google Chrome  Google LLC  accounts.google.com            142.251.127.84  443 TCP CA Montreal      1927 1412
```
All Chrome helpers fold into "Google Chrome". Chrome picked QUIC/HTTP3, so the row is 443 **UDP**, not TCP. Resource Monitor can't be scripted from here, so the byte ballpark was checked against curl's own counters (above). Worth a glance in Resmon during the final acceptance test.

**Signer vs `Get-AuthenticodeSignature` (6/6 agree):** notepad, curl, svchost, explorer → `Microsoft Windows` (catalog); chrome → `Google LLC`; outboundctl.exe → Unsigned.

**SQLite (`destinations`):** `('exe:c:\windows\system32\curl.exe','speed.cloudflare.com','cloudflare.com','162.159.140.220',443,'Tcp',697,5012932,1,'CA','Toronto',…)`; samples=219, connections=1035, apps=28.

**Fallback (`--no-etw`, IP Helper + DNS cache):** 82 flows, 72 with hostname (e.g. `Brave Browser · Brave Software, Inc. · api.anthropic.com · anthropic.com · 160.79.104.10:443 · US San Francisco`), bytes 0 by design.

**Tests:** 74/74 pass (was 46): PSL incl. wildcard/exception rules, 3008 result parsing, DNS wire parsing, DnsMap precedence, GeoIP local ranges + bundled DB, signer (catalog / unsigned), enforcer hostname → IPs, dry-run default.

**Not done in Phase 1 (UI-side, Phase 3):** exe icon extraction (needs WPF imaging); the "N processes" expandable list is UI. The data is there: `AppInfo.Key` groups PIDs.

## Phase 2 — rules, modes, enforcement (DONE)

### Rule model (SPEC Phase 2)
- `Rules/Rule.cs` rewritten: adds `DestKind` (Any/Host/Domain/Ip/Cidr/LocalNetwork), `ProtoSpec` (Any/Tcp/Udp), Direction ("out"), `Enabled`, `Profile`, `Source` (user/blocklist/profile/ai/imported/pending/learned), `Consumed` (Once), `SessionKey`/`BootKey` (Until Logout/Restart), `IsPriority` flag (Priority>100), `Note`.
- `RuleMatcher.Matching(...)` returns the full best-first list (priority → specificity → deny-wins → id) so the engine can act on the top match while `explain` shows it; `DestMatches(rule, ctx)` now uses **hostname from the flow** for Host/Domain kinds (so domain rules match by SNI/DNS name even when the IP isn't in the DNS cache), CIDR+IPv6, LocalNetwork via `GeoIp.IsLocal`.
- App match made bidirectional: a full-path matcher matches a flow seen by name and vice-versa (a rule made from `C:\Windows\System32\curl.exe` matches a worker-PID flow that only reported "curl.exe"). This was the one real behaviour bug found during the live phase-2 test.
- **Lifetimes** `Policy/SystemKeys.cs`: Until Restart = kernel BootId (fallback boot time); Until Logout = WTS session id + that session's logon time (same for elevated/normal tokens). `Rule.StampLifetime` writes the keys at creation; `IsExpired` compares them, so login/reboot expires them without a timer.

### Modes + policy + safety
- `Policy/PolicyEngine.cs` (pure, no I/O): Learn = allow+review, Ask = prompt, Strict = deny+review; **safety net** — DNS(53)/DHCP(67,68)/DHCPv6(546,547)/NTP(123) and core-networking processes are always allowed so Strict can't orphan the machine; unknown-identity flows are allowed, never blocked blind. **Trust break**: an ALLOW rule whose app binary hash/signer no longer matches is suspended (treated as brand new) unless the source is learned/pending.
- `Policy/PolicyService.cs` wires FlowStarted → decision, logs review rows, tracks Ask prompts with `Policy/PromptManager` (8 s UDP / 60 s TCP, clamp 15–120), `Policy/ReviewStore` (pending/learned/blocked rows), `Policy/AppTrustStore` (same-binary hash + signer, deterministic FNV-1a-64 hash — deliberately not crypto; the binary's real signature is the security boundary).

### Enforcement (dry-run)
- `Policy/EnforcementPlanner.cs`: translates deny rules into netsh commands **using the resolved/observed IPs** (never the hostname), with a DNS-observed-IP union hook; diffs against installed `OutboundWin *` rules so it's idempotent and never touches foreign rules; deny-any is skipped in v1 (too broad).
- `outboundctl enforce` shows the diff; real `--apply` gated on your approval (dry-run by default, SPEC §0.5).

### Evidence
Unit tests **92/92** (lifetimes incl. UntilLogout/Restart/BootId, disabled, subdomain+resolved-IP matching, protocol filter, priority-flag, Strict/Learn/Ask, safety net, enforcement plan/idempotence/unresolved-skip, review→answer flow).

Live (deny rule for `example.com` for `curl.exe`, port 443):
```
$ outboundctl explain --app curl.exe --host example.com --port 443
Decision: deny
Decided by: rule 1: Deny connections to example.com (and subdomains) on port 443 for curl.exe, for 1 hour   (exit=3)
$ outboundctl explain --app notepad.exe --host example.com --port 443 → allow (no matching rule)
$ outboundctl enforce   → dry-run  to-add=1
  would run: netsh advfirewall firewall add rule name="OutboundWin 1" dir=out action=block enable=yes program="C:\Windows\System32\curl.exe" remoteip=104.20.23.154,172.66.147.243
$ watch (real curl to https://example.com, live decision):
DENY pid=9304 The curl executable -> example.com:443/TCP  rule 1: Deny connections to example.com (and subdomains) on port 443 for curl.exe, for 1 hour
```
Real firewall application (`--apply`, the SPEC "done when" curl block) is **held dry-run pending your explicit OK** — it changes the Windows Firewall, which needs your go-ahead.

### Nightmare noted (languages)
A big chunk of Phase-2 time burned on the C# dialect this toolchain uses: `or`/`and`/`base`/`out` (`var out`) are reserved/syntactically rejected, string interpolation crashes on `?:` ternaries and on conditional concat `.. + ..`, `return switch` is unsupported (only `=> switch` assignment), `DateTime` has no `ToIsoString`/`ToUnixTimeSeconds` (use `ToString("O")`/`Parse`), net8.0 full-build dependency resolution differs from incremental. All resolved; files are clean now. Worth keeping in mind for Phase 3.

## Phase 3 — UI (IN PROGRESS)

### Item 1: WPF-UI styling + light/dark theme — DONE (2026-10-12)
- `Outbound.App.csproj`: added **WPF-UI** package. Note: 3.4.2.7 no longer resolves on NuGet (NU1603 → approximated to 4.0.0), so pinned explicitly to **4.0.0** (current stable; same theme API).
- `App.xaml`: merged `ui:ThemesDictionary Theme="Light"` + `ui:ControlsDictionary` (default Light per SPEC "clean, light look"); restored `StartupUri="MainWindow.xaml"`.
- `App.xaml.cs`: OnStartup applies persisted theme via `ApplicationThemeManager.Apply(theme, WindowBackdropType.Mica)`; new static `ThemeSettings` persists `"theme":"Light|Dark"` to `%LOCALAPPDATA%\OutboundWin\settings.json`; OnExit saves.
- `MainWindow.xaml`: restyled as `ui:FluentWindow` — WPF-UI buttons in toolbar, all hardcoded dark hex colors replaced with theme-aware DynamicResource brushes (TextFillColorPrimary/Secondary, CardBackgroundFillColorDefault/Secondary, SolidBackgroundFillColorSecondary, DividerStrokeColorDefault, ApplicationBackground); card style for the add-rule form.
- `MainWindow.xaml.cs`: base class → `FluentWindow`; new **Dark mode / Light mode** toggle button (applies theme live + persists) and **Remove OutboundWin firewall rules** button wired to `FirewallEnforcer.Clear()` honoring the dry-run checkbox; `MessageBox` aliased to System.Windows (WPF-UI 4.0 adds its own MessageBox type).
- **Verified**: build clean (0 warnings, 0 errors); app launched and main window visible (`Outbound - outbound firewall monitor (PoC)`, HWND confirmed via EnumWindows); full test suite **92/92 pass**.

### Item 2: Tray icon + flyout panel — DONE (2026-10-12)
- `Outbound.App.csproj`: added **H.NotifyIcon.Wpf 2.3.2** (SPEC names it; 2.4.1 dropped the net8 target → NU1701, so pinned to last net8-compatible).
- `App.xaml.cs` rewritten: OnStartup creates `TaskbarIcon` with a generated "O" glyph (`GeneratedIconSource.ToIcon()` — no assets/ yet) and sets `TrayPopup = Flyout`; new public `Flyout` property; Tray disposed in OnExit.
- New `TrayFlyout.xaml/.cs`: status line, Learn/Ask/Strict toggle buttons (set `Policy.Engine.Settings.Mode`), counts line (`apps · allowed · blocked` from new `PolicyService.Counts()`), recent-5 connections list (✓/✗ marks from flow Decision), **Open Outbound** (restore+activate main window via new `MainWindow.ShowFromTray()`), **Pause 15 min** (auto-resume timer) / **Turn off**. Refreshes every 2 s.
- `PolicyService` (Core): added `volatile bool Enabled` gate — while false, `OnFlow` skips evaluation/recording entirely; plus `Counts()`. Dry-run untouched: pausing only stops policy evaluation, never firewall state.
- `MainWindow`: exposes `Engine`/`Policy`, wires flyout on Loaded.
- **Verified**: build clean (0 warnings/errors); app launched, main window visible + process stable >60 s; 92/92 tests pass. Tray icon itself not visually confirmable — Hermes runs elevated so the tray lives on the hidden admin desktop; TaskbarIcon construction is exception-free and the flyout wiring path executed (an earlier NRE from a missing `InitializeComponent()` in TrayFlyout was found via WER event 1026, fixed).

### Item 3: Connection prompt window (Ask) — DONE (2026-10-12)
- `src/Outbound.App/AskWindow.xaml` + `.xaml.cs`: plain WPF `Window` (not FluentWindow — a second FluentWindow after the first closed crashed the app; plain Window is safe to create repeatedly). `ShowActivated="False"` so it never steals keyboard focus from whatever you're typing in. Topmost, centered, SizeToContent=Height.
- **Segmented pickers** (user fix #1): Lifetime and Scope are RadioButton groups styled as segmented buttons (`Style x:Key="Seg"`, CornerRadius 6 border; checked = accent fill + white text so the selection is always visible). Defaults per SPEC: lifetime = **Forever**, scope = **This port only**.
- **Enter/Esc can't answer** (user fix #3): Deny and Allow both have `IsDefault="False" IsCancel="False"`; buttons also stay disabled for ~1 s after each question appears so a stray keystroke can't decide.
- One prompt at a time + side queue ("Waiting (N)") with "Answer all for this app"; countdown line shows the timeout outcome (allow vs block per `BlockWhenPromptUnanswered`).
- Wiring: `App.EnsureAsk(policy)` get-or-create (Closed → null ref, next prompt makes a fresh window; `Show()` guarded by IsVisible); MainWindow pumps NewPrompt/Resolved/TimeoutDecision onto it. `--mode ask|learn|strict` CLI flag forces the mode for testing until Settings UI lands.
- **Verified live** (UIA tree of the real window): "Forever" checked=True, all other lifetime options False; "This port only" checked=True, others False; Deny/Allow enabled after 1 s; foreground window unchanged before vs after prompt appeared → focus not stolen. Build clean 0W/0E; 92/92 tests pass.

### Item 4: Main window — NavigationView with all pages — DONE (2026-10-12)
- `MainWindow.xaml` restructured: the WPF-UI **NavigationView** in this build (4.0.0) rejects a plain content child (MC3028 "cannot add content") — the nav is now a **Left-docked menu pane only**, and the six stacked pages live in a sibling fill `Grid` that the code-behind shows/collapses. Removed read-only `Id` attributes (MC3065) and `IsSelected` (no such property here; items expose `IsActive`).
- `MainWindow.xaml.cs`: `Nav.SelectedItem =` setter is inaccessible in WPF-UI → initial selection set via `NavOverview.IsActive = true` + explicit `ShowPage("overview")`. All pages present: **Overview / Activity / Rules / Review / Map / Settings**, with toolbar (Refresh now, dry-run check, Apply/Clear firewall rules, dark-mode toggle, "Network not working?" Help), Rules grid, Review grid with allow/block/dismiss buttons, Settings.
- Known fixes from the build cycle (compiler-driven): added missing `using Wpf.Ui.Controls;`, qualified `System.Windows.Threading.DispatcherTimer`, fixed ambiguous `Button` → `Control` casts, **ReviewRowVm** built with named args (class with init-props, not a record), `BtnAllowVerified` now uses new `AppResolver.ResolveByExe(exe)` (it was casting a string AppKey to int — dead for review rows with no live PID), and replaced `try { _engine.Start(); } catch { }` with logging + **"Monitoring unavailable: <reason>"** status line.
- New **HelpWindow** ("Network not working?"): plain WPF `Window` (safe to create repeatedly, like AskWindow), shows blocked count + recent blocked hosts, Pause 15 min / Turn off / Close.
- **Verified live** (UIA tree of the running app): main window `Outbound — outbound firewall monitor` with all six nav items (Overview, Activity, Rules, Review, Map, Settings) + toolbar controls present; Ask window (real Microsoft prompt) shows **Forever** and **This port only** `selected=True`, all others False, Deny/Allow present. Build clean **0W/0E**; tests **92/92 pass**.

### Item 5: Activity page — smart-filter tokens, time-range picker, sparklines — DONE & verified (2026-10-12)
- **Tokens** (`MainWindow.xaml` + `.cs`): search box + 8 checkbox tokens (ai apps, ads/tracking, new apps, unsigned, microsoft services, local network, abroad, heavy users). `ApplyActivityFilter()` is the single filter path — called by search text change, each token toggle, and range selection; free-text and tokens combine (OR within a token's host list, AND across active filters). "New apps" = first flow seen this session (`_appFirstSeen`); "heavy users" = ≥10 MB session bytes.
- **Time-range picker**: `CmbRange` combo (Last 5 min / 30 min / hour / 6 hours / All time default) — filters destinations by last-seen inside the window; `RangeNote` shows "since HH:mm".
- **Sparklines** (`ScottPlot.WPF 5.*`, pinned via `5.*` → restored 5.1.59): per-app last-hour bytes, bucketed per UTC minute from session-total deltas each render tick (no new data source — read-side only). Rendered off the WpfPlot control: `plt.GetImage(138,40)` → `ScottPlot.Image.GetImageBytes()` (PNG) → frozen `BitmapImage` bound to an `Image`. Transparent background (`FigureBackground`/`DataBackground` = #00000000) so it blends in both themes. Wrapped in try/catch — sparkline is cosmetic and never breaks the render loop.
- **App-grouped list**: Activity rows are now app groups (`AppGroupVm`) with expandable destination sub-rows (`DestRowVm`); persistent `_groups` dict survives rebuilds; 500 ms render throttle. Inspector reworked to evaluate the selected group's primary flow via `RuleMatcher.Decide` (single evaluation point unchanged — `_policy.Attach(_engine)`).
- **New CLI arg** `--page overview|activity|rules|review|map|settings` (`App.xaml.cs` + MainWindow Loaded) — launches directly on a page; also unblocks Phase 5 CLI work.
- **Verified live via UIA automation** (synthetic mouse clicks can't activate WPF-UI NavigationViewItem, so `--page activity` launch + UIA patterns): token "local network" toggle filtered groups 2→3→2 with correct signer sublines; range picker selected "Last 5 minutes" → RangeNote "since 13:16", restored to All time; search box (ValuePattern) narrowed list to the Python group, cleared back. Sparkline confirmed in screenshot: blue line on transparent/dark background in the app-group row. Build **0E** (2 expected NU1701 SkiaSharp warnings).
- Next: **Phase 4 — offline WebView2 map/globe.** DONE & verified (see below).

### Item 6: Phase 4 — offline WebView2 map/globe — DONE & verified (2026-10-12)
- **Offline assets** bundled in `src/Outbound.App/web/` (copied to output): d3-array@3 + d3-geo@3.1.1, topojson-client@3.1.0, world-atlas countries-110m.json (177 features), globe.gl@2.34.5 UMD (self-contained three.js). No network at runtime.
- **WebView2 host** (`MainWindow.xaml.cs`): `InitMapWeb()` best-effort — user-data dir under `%LocalAppData%/OutboundWin/webview2`, fallback panel if no runtime. Assets served via `SetVirtualHostNameToFolderMapping("appassets", …)` → page at `https://appassets/map.html` (file:// blocks all sub-resource fetch/XHR in WebView2).
- **Data pipeline**: `PushMapData()` every ~1 s while Map visible — origin Abu Dhabi + per-city dests (lat/lon from GeoIp, bytes, blocked flag) + last-hour minute buckets. **Pitfall: `PostWebMessageAsJson` is a silent no-op on WebView2 1.0.2973.100** — injection done via `ExecuteScriptAsync("window.__push('…')")`.
- **map.js**: 5 themes (graphite/bluemarble/midnight/daylight/amber), 2D d3 map (Natural Earth, great-circle arcs via `d3.geoInterpolate` — v3 has no geoGreatCircle) + 3D globe.gl toggle, top-places list with hover tooltips, last-hour traffic chart with **drag-to-filter** window, blocked routes/points in red.
- **Verified live**: countries render (177 features), arcs from Abu Dhabi to ~20 real cities, globe mode renders at full canvas size (div container — passing a `<canvas>` bypasses sizing; `globeColor` doesn't exist → `globeMaterial().color.set()`). One-shot JS self-test via C# probe: **themes ok(5), drag-filter ok** (window set + rangeNote "10:23–10:25 UTC"), places=16. Build 0E.
- Next: **Phase 5 — CLI / MCP / IPC / extras.**

## Phase 5 — CLI / MCP / IPC / extras (IN PROGRESS)

### Item 1: outboundctl ↔ running app over named pipe — DONE & verified (2026-10-12)
- `IpcServer` (app side): named pipe `OutboundWin`, current-user-only ACL + explicit NETWORK-SID deny; one JSON object per line. Commands: status, mode.get/set, rules.list/count/add/remove/enable/disable, explain, export.jsonl.
- **Bug found via the new error path** (client prints server's `error` text; server logs full exception to `%LocalAppData%\OutboundWin\ipc.log`): client sends args **flat at the JSON root**, server only read a nested `"args"` object → `Explain` got an invalid JsonElement (`InvalidOperationException: Operation is not valid due to the current state of the object`). Fixed: accept both shapes. Second latent bug in same path: `ToProto(null)` NRE when client sends `"proto":null` (the CS8604 warning) — coalesced to "".
- **Verified live** (non-elevated outboundctl → elevated app):
```
$ outboundctl status        → mode=Learn  dry-run=true  flows=125  rules=5 (enabled 5)  uptime=16s
$ outboundctl mode get      → Learn
$ outboundctl rules count   → total=5 enabled=5 disabled=0
$ outboundctl explain --app curl.exe --host example.com --port 443
Decision: allow
Decided by: rule (default) - no matching rule
  matching #1: Deny connections to example.com (and subdomains) on port 443 for curl.exe, for 1 hour   (exit=0; deny would exit 3)
```
- Next: **Item 2 — MCP server over the pipe with an approval dialog for rule changes.** DONE & verified (see below).

### Item 2: outbound-mcp over the named pipe + approval dialog — DONE & verified (2026-10-12)
- `outbound-mcp` v0.1.0 → **v0.2.0**: read-only tools (`list_flows`, `explain_flow`, `list_rules`) now route through the app's named pipe so figures match the UI; they fall back to local SQLite/OS tables when the app is not running (labelled in the result).
- **`propose_rule`** no longer returns a copy-paste command — it calls the new `rules.propose` IPC command, which blocks the pipe thread on `_win.Dispatcher.Invoke` and shows an **ApprovalWindow** (topmost, 60 s countdown, auto-deny on timeout; Enter/Esc disabled so an unattended agent can't slip through). The rule is applied ONLY if the user clicks Approve.
- New app files: `ApprovalWindow.xaml` + `.xaml.cs`. Server side: `IpcServer.RulePropose` (shared `ParseRule` with `RuleAdd`).
- **Pitfall hit**: first dialog render threw `Set property 'TextElement.Foreground' threw an exception` — WPF theme resources are `*Brush`-suffixed (`ApplicationBackgroundBrush`, `CardBackgroundFillColorSecondaryBrush`, `TextFillColorPrimary/SecondaryBrush`), not the bare names. Fixed in XAML; build 0E.
- **Verified live** (MCP over stdio → app): `tools/list` returns all 4 tools; `list_rules` returned the app's live 5 rules via pipe; `propose_rule {deny example.com curl.exe:443 1h}` → dialog shown, auto-denied on timeout → MCP got `"DENIED — … Nothing was changed."`; `outboundctl rules count` still `total=5 enabled=5 disabled=0` (nothing applied). Approve-path not clicked in this run (timeout path exercised end-to-end); the Approve branch is the same `RuleAdd` code already verified in Item 1.
- Next: **Phase 6** per SPEC, or user's call.

### Step-1 quick fixes (2026-10-12)
a) **Firewall rules**: `netsh advfirewall firewall show rule name=all` → **zero** rules matching "OutboundWin" (case-insensitive). Nothing to remove; enforcement stayed dry-run as required.
b) **LangVersion**: searched all 5 `.csproj` + any `Directory.Build.props` — no `<LangVersion>` anywhere (SDK default = latest for net8.0). No change needed; build/tests unaffected.
c) **NDIS capture filter**: `EtwNetworkCollector.OnDns` only consumes NDIS-PacketCapture event 1001 frames, and `DnsWire.TryExtractDnsFromEthernet` discards any frame whose UDP source port ≠ 53 (one int compare per frame; non-DNS traffic is never parsed or stored). TraceEvent's `EnableProvider` has no truncation parameter for this provider — full frames arrive on the receive path, so "truncated packets" isn't a knob we control; effective filter = **port-53 UDP only**.
   - **Known limitation (DoH)**: DNS-over-HTTPS (Chrome/Edge built-in resolver) is encrypted on port 443 — no name to parse. Those flows show the IP instead of the hostname until a plain-DNS event for the same IP arrives (DnsMap back-fill). Accepted as v1 behaviour; noted per SPEC Phase 1 finding #2.

### User fix 1: explain listed an expired rule as matching — DONE & verified (2026-10-12)
- **Root cause**: `IpcServer.Explain` built its "matching" list with an inline filter that checked Enabled/App/Dest/Port but NOT expiry, while the real decision path (`RuleMatcher.Decide`) does check `IsExpired`. So a 1-hour rule showed as both "Decided by: (default) - no matching rule" and "matching #1".
- **Fix**: extracted the exact live predicate into public static `RuleMatcher.LiveMatch(rule, ctx)` — Explain now uses it for its matching list, so explain and Decide can never disagree. Expired matches are reported separately in a new `expiredMatches` field; outboundctl prints them under an "expired" section (greyed, not counted as matching).
- **Unit tests** (3 new): `ExpiredRule_IsSkipped`, `LiveMatch_ExcludesExpiredRule`, `LiveMatch_IncludesLiveRule`.
- **Verified live**: the expired rule #1 now appears only under "expired", decision stays allow with "(default) - no matching rule".

### User fix 2: pipe blocked while approval dialog open — DONE & verified (2026-10-12)
- **Root cause**: `NamedPipeServerStream` was created with maxInstances=1; `rules.propose` blocks its connection on the dispatcher up to 60 s, so every other outboundctl/MCP call queued behind it.
- **Fix**: pipe now allows **MaxInstances = 16**; each accepted connection is served on its own `Task.Run(Serve(...))`. The propose connection stays blocked in its task; all others get a fresh instance immediately.
- **Verified live** (the user's exact test): started `propose_rule` via MCP, dialog open → `time outboundctl status` answered in **118 ms**. After the 60 s timeout: auto-deny fired, rules unchanged (`total=5 enabled=5`).

### Item 3: Profiles per network — DONE & verified (2026-10-12)
- **Core**: `Network/NetworkWatcher.cs` polls every 5 s and raises `Changed(networkName)`; `Policy/ProfileService.cs` holds profiles (`name`, `mode`), the active profile, a network→profile auto-switch map, persists to `%LOCALAPPDATA%\OutboundWin\profiles.json`.
- **Semantics** (unit-tested): untagged rules apply on every profile; tagged rules only when their profile is active. Active profile's mode drives `Engine.Settings.Mode` via the service's Changed event.
- **UI**: Settings page "Profiles — per network" card: current network, profiles list with delete, add form (name + mode), active-profile selector, "map this network → selected profile". Rules grid gained a Profile column (`(all)` when untagged).
- **CLI/IPC**: `outboundctl profiles` (network / activeProfile / profiles / auto-map); `rules add --profile NAME`; rule list shows `prof=`.
- **Pitfalls hit on this machine**: (1) INetworkListManager's IID is `DCB00C01-…`, not its CLSID — first version QI'd the wrong interface and silently got nothing; (2) NLM COM calls need a COM apartment (`CoInitializeEx` on the watcher thread); (3) **NLM is unavailable here** (E_NOINTERFACE from both IIDs, no NetworkListService) → added `System.Net.NetworkInformation` fallback for physical adapters.
- **Verified live**: `outboundctl profiles` → `network=Ethernet  activeProfile=(none)`; rule #7 created with `--profile work` shows `prof=work`; tagged-rule filtering covered by the two new unit tests (97/97 total).

### Item 4: Blocklists over HTTPS — DONE & verified (2026-10-12)
- **Core**: `Policy/BlocklistService.cs` — domain trie (exact-or-subdomain matching; entry `ads.example.com` also blocks `x.ads.example.com`, parent is NOT blocked by child). Subscriptions fetched over HTTPS (`HttpClient`), parsed as hosts-format or plain-domain lists, per-sub disk cache at `%LOCALAPPDATA%\OutboundWin\lists\<name>.txt`. **Fail-safe**: on fetch failure the last good list stays active and `LastError` is surfaced. Each trie node tracks which lists contain it (`Subs`) so `WhichList()` attributes a hit to a named list for explain/audit.
- **Policy semantics** (unit-tested): blocklist check runs AFTER the rule loop — an explicit ALLOW/DENY rule wins over the list; before the mode fallback, so Learn/Ask/Strict all deny listed hosts. Disabled subs are skipped.
- **UI**: Settings page "Blocklists" card — total loaded entries, per-sub rows with status (✓ fetched / ⚠ last fetch failed — cached list in use), add form (name + URL). `Changed` events marshal to the dispatcher so background fetches refresh the UI live.
- **CLI/IPC**: 5 commands (`blocklists.list/add/remove/toggle/refresh`) + `outboundctl blocklists …`; `explain` now reports `Decided by: rule (blocklist) - blocklist '<name>': host <host> is listed`.
- **Bugs found & fixed during verification**: (1) Save() wrote PascalCase keys but Load() read camelCase → every restart produced a corrupt empty sub; fixed with `JsonNamingPolicy.CamelCase` + defensive skip of nameless entries, regression test added. (2) Explain's blocklist reason was assigned even when no list matched — moved inside the null-check.
- **Unit tests** (5 new): exact+subdomain deny via engine, explicit-allow-wins, failed-fetch keeps last good list, multi-list attribution, persistence round-trip. 102/102 total.
- **Verified live** (local HTTP server serving a hosts-format list): add → `loaded entries=2`; explain on listed host → `Decision: deny … blocklist 'testlist'` (exit 3); subdomain of a listed entry also denied; clean host allowed; disable/enable toggles the decision; refresh re-fetches; **app restart** keeps the persisted list active; with the server killed, refresh fails and the cached list still denies.

## SPEC-UI redesign — §0 Map fixes (DONE, awaiting user check)

SPEC-UI.md is now the priority (match the Mac app). Order: §0 map → window shell → Network Monitor → Overview → All Rules → Review → motion.
Note: the four `reference/mac-*.png` files named in SPEC-UI are not in `reference/`; the Mac app's own screenshots there are the `*-light.webp` set, which SPEC-UI's written description matches — those were used.

### §0.1 View fits the traffic, not the USA
- 2D map is now **Leaflet 1.9.4** (`crs: L.CRS.EPSG4326`, the raster is equirectangular) instead of a plain d3/SVG vector map.
- `fitToData()` frames **origin + every destination** with 60 px padding (`fitBounds`, maxZoom 6); with no destinations it centres on the origin at zoom 4 (regional). It re-fits on data/refresh while the user has not moved the view, and pulls the view out when a new place lands outside it (`userMoved` set on real drag/zoom events only).
- Live: `2d-direct: loaded 8192x4096 20svg 824x507 c=14.17,-22.43 z=1.25` — with a worldwide destination set the fitted view is a world view whose centroid sits mid-Atlantic; the origin (Abu Dhabi) and all arcs are inside it.

### §0.2 Origin = this PC's location
- Settings › **Location** card: editable, type-searchable city picker over a bundled **243-city** Natural Earth list (`assets/cities.json`, public domain), default **Abu Dhabi, UAE**; saved to `settings.json` (`originCity/originCountry/originLat/originLon`).
- `GetMapOrigin()` now reads the picker (previously a GeoIP lookup of 8.8.8.8 with an Abu Dhabi fallback). Changing the city clears the cached origin and pushes immediately, so the map re-centres.
- Origin is drawn as a **blue circle with a laptop icon** (`divIcon`), and every arc starts from it.
- Verified via UIA: combo value `Abu Dhabi - United Arab Emirates`, hint `Origin: Abu Dhabi … (24.467, 54.367)`.
- **Settings file no longer clobbered**: theme, policy settings and location all write through `AppSettingsFile.Update()` (merge) — previously each writer rewrote the whole JSON, so saving one key erased the others.

### §0.3 Real imagery, fully offline
- Bundled **NASA Blue Marble** (topography + bathymetry, public domain) and **Natural Earth II shaded relief** (public domain) at **8192×4096** equirectangular JPEG (`web/bluemarble.jpg` 3.4 MB, `web/ne2-relief.jpg` 3.8 MB). No tiles are fetched at runtime.
- Map style buttons (top of the map): **Satellite** (Blue Marble, darkened ocean — default), **Standard** (Natural Earth relief), **Muted** (desaturated dark), applied as CSS filters on the raster layer.
- Borders/coastlines from the existing bundled `countries-110m.json`; city labels (top 10 destinations) as `divIcon` text with a dark outline; dot hover tooltips.
- The **3D globe uses the same Blue Marble texture** (`globeImageUrl("bluemarble.jpg")`, verified `globeTexture: bluemarble.jpg`) on a **dark night sky** (starfield background + atmosphere).
- Self-test evidence: `styles: satellite,standard,muted`, `raster: loaded 8192x4096`, `drag: ok`, `2d-after-3d: loaded 8192x4096 20svg` (the SVG-detach bug stays fixed), `leaflet: 1.9.4`, build **0 errors**, 129/129 tests still green.

### Screenshots
- `screens/map-v2.png` — 2D satellite map, arcs from the Abu Dhabi origin, city labels, top-places list.
- Next: **window shell** (sidebar + top bar) per SPEC-UI §1 — waiting on the user's OK for §0.

## SPEC-UI — themes (System/Light/Dark/Midnight) + compact Activity window (DONE, awaiting check)

### Themes — Settings › Appearance, live, no restart
- Four options: **System** (follows Windows), **Light**, **Dark (graphite)** = today's look, **Midnight**. Persisted as `settings.json:"theme"`; the toolbar toggle quick-cycles Dark → Light → Midnight → Dark.
- Each is its own dictionary with the same key set: `Themes/Light.xaml`, `Themes/Graphite.xaml`, `Themes/Midnight.xaml`. `ThemeManager` swaps the WPF-UI base theme, merges the palette last, re-merges it on `ApplicationThemeManager.Changed` (WPF-UI otherwise re-asserts its own brushes), applies window chrome, and saves.
- Midnight: window gradient **#0B1322 → #101B2E** (measured 11,19,34 → 16,27,45), 1 px #22314D border, corner radius 20, cards ~8 % white fill / 10 % white border / radius 12 / soft shadow, text #E8EEF7 + #8A97AD, chips #1E2B44/#A9B4C8, toggle track #1E2A40, green #2FBF5B, red #E5484D, orange #F5A524, blue #3B82F6, search pill 5 % white fill + 10 % border.
- The map follows the theme (`theme` is pushed with the map payload): Midnight = navy page background, navy zoom controls, navy-tinted raster, navy globe background.
- **Bug found by measuring pixels**: 8-digit hex is `#AARRGGBB`, so my "#FFFFFF14" (meaning 8 % white) was *opaque yellow* — cards rendered yellow. Fixed to `#14FFFFFF` etc. across the palettes.
- **Bug 2**: WPF-UI re-asserted its stock background/card brushes over the palette (text keys applied, fills did not) → palette now re-merges on WPF-UI's change event, and the app's Card style + root panel use the app's own `App*` keys.

### Compact Activity window (`CompactWindow`)
- Opened from the top-bar **Activity** button (LayoutColumnThree24) and the tray menu ("Activity feed"); also `outboundctl ui compact` (new IPC `ui.compact`) for automation.
- Header: **Activity** bold, green dot + "N seen today" (true uncapped destination count), search pill "Apps, hosts or ports" (filters app/host/port), pin (always-on-top) + close.
- Rows newest-first: app icon in a white 10 px-radius tile, host with the main domain bold, sub-line app name + a `443 · TCP` chip + country code + city, relative time ("now", "6 s", "25 min").
- Decision pill ✕ | ✓: allowed fills the ✓ side green, blocked fills the ✕ side red (fill animates in over 180 ms), waiting gets an orange 1.5 px pill outline. Clicking either side creates the same rule the CLI creates (host rule for that app + port/proto, `RuleSources.User`) via `MainWindow.CreateRuleFromCompact`.
- New rows slide in from the top (200 ms ease-out, `TranslateTransform` −18 → 0 + opacity) and push the list down; the list's bottom fades out via an `OpacityMask` gradient.
- Window: 800×650, resizable, borderless glass (WindowChrome, radius 14, drag on the header, double-click to maximize), remembers position/size and the always-on-top flag in `settings.json`.
- Bug: the pin rendered nothing because `Loaded` set `BtnPin.Content = null`; icon-only buttons also got `AutomationProperties.Name` so Narrator does not announce anonymous buttons.

### Screenshots
- `screens/midnight-overview.png` — the existing pages under Midnight; `screens/compact-activity.png` — the compact feed.
- Icon audit: all 57 candidate `SymbolRegular` names used in the redesign were verified by rendering to a bitmap (throwaway probe), so no icon renders blank.
- Next: SPEC-UI §1 **window shell** (240 px sidebar with the new sections/counts, status pill, glass cards) — waiting on the user's OK.

## SPEC-UI — Aurora theme (default) + bundled fonts (DONE, awaiting check)

### Aurora — 4th theme, now the default
- `Themes/Aurora.xaml`, same key set as Light/Graphite/Midnight; a 4th option in Settings › Appearance (listed first as "Aurora (default)") and the default when `settings.json` has no theme. Live-switchable with the others; `outboundctl ui theme Aurora` for automation.
- Palette as specified: ink `#0D0F1A` + violet `#8B5CF6` (top-left) and teal `#22D3EE` (bottom-right) glows at 8%, cards `#161A2B` at 85% with a 1px `#262B42` border and radius 12, sidebar `#11131F` at 80%, selected nav pill = violet 18% with a violet icon, rows `#1B1F33`, dividers `#20243A`, text `#ECEEF7`/`#8B90A8`, chips `#20243A`/`#B7BCD4`, accent violet with hover `#9D74F7`, mint `#34D399` allowed · coral `#FB7185` blocked · amber `#FBBF24` asking · cyan `#22D3EE` received · peach `#FB923C` sent · violet `#C084FC` AI, 15% tints, dark glyphs inside filled circles (`#0D2A1F` on mint, `#3A0E18` on coral).
- Map follows: ink background, **mint arcs for allowed / coral for blocked**, cyan chart line, glass overlays `rgba(22,26,43,0.55)` + `backdrop-filter: blur(18px)` on the map's bars/pages.
- Applied to every page and window through the shared keys — Ask, Approval, Help and the tray flyout contain **no hardcoded colours**, so they re-skin automatically.

### Fonts (SIL OFL 1.1, bundled offline)
- `Fonts/` holds static TTFs: Plus Jakarta Sans Regular/Medium/SemiBold/Bold and JetBrains Mono Regular/Medium, plus `OFL.txt` (both licences) — credit lines added to Help and a new Settings › About card.
- Type scale in `Themes/Typography.xaml` (page title 30 Bold, section 17 SemiBold, row 14 SemiBold, body 13, caption 11.5, stat numbers 22 JetBrains Mono Medium, mono for ports/times). `ContentControlThemeFontFamily` is overridden so every WPF-UI control uses Plus Jakarta Sans.
- **Gotchas paid for here**: static TTFs report weight-suffixed families (`Plus Jakarta Sans SemiBold`), so each weight is its own FontFamily; and `<Resource Include>` alone does **not** embed them — the SDK's default `None` glob wins, so `None Remove`/`Content Remove` first (verified with a `ResourceReader` over `Outbound.g.resources`).
- Fonts verified live: same string measured over UIA — bundled font **232 px** vs Segoe UI **220 px** (`TextBlock.Measure()` and `RenderTargetBitmap` were both false negatives; WPF's fallback for an unknown family *is* Segoe UI).
- Screenshot pipeline note: the first Aurora build captured **blank** frames because the glow layer used giant blurred ellipses; replaced with corner-origin gradient rectangles (same look, PrintWindow works again).

### Screenshots
- `screens/aurora-overview.png` — Overview under Aurora; `screens/aurora-compact.png` — the compact Activity feed (mint ✓ with a dark glyph, mono ports/times).
- Next: SPEC-UI §1 **window shell** (240 px sidebar, new sections with counts, status pill) — waiting on the user's OK.

## BUG: every byte count showed 0 after a normal launch (FIXED, awaiting UI confirmation)

### Root cause
The exe's embedded manifest was the SDK default **`requestedExecutionLevel level="asInvoker"`** — the app never elevated on a normal launch (shortcut / double-click). Real-time ETW kernel sessions are admin-only, so `EtwNetworkCollector.CanRun` was false, `Start()` skipped ETW entirely, and the engine fell back to the **IP Helper snapshot, which has no byte counters by design**. The status bar even said so (`iphelper · user-mode (blocking needs admin)`) but nothing surfaced it as an error, and the Overview showed zeros as if there were no traffic.

### Fixes
1. **`app.manifest` with `requireAdministrator`** (+ `PerMonitorV2` DPI, longPathAware), wired via `<ApplicationManifest>` — a normal launch now elevates and ETW starts.
2. **`engine.log`** (`%LocalAppData%\OutboundWin\engine.log`, `Outbound.Core.Engine.EngineLog`): logs elevation, stale sessions stopped, each session started, reader-thread exit, and the **exact exception** on failure (`MONITORING OFF: …` + full stack). The reader threads no longer swallow exceptions (`catch { }` → logged), so a dead reader can't silently produce zeros.
3. **Stale sessions are stopped and restarted** (already present, now logged): live evidence `stale sessions stopped before start: OutboundWin-Net, OutboundWin-Dns` → both restarted → `live monitoring started (ETW)`.
4. **Single instance**: named mutex `Local\OutboundWin.SingleInstance`; a second launch sends IPC `ui.activate` (brings the first window forward) and exits. **`Environment.Exit(0)`, not `Shutdown()`** — with `Shutdown()` the WPF framework still built MainWindow after `OnStartup` returned, its engine started, and its `StopStaleSessions()` killed the *running* instance's ETW sessions (observed: the first instance's readers exiting). Verified fixed: second launch logs only the handoff, one process remains, first instance kept counting (1084 → 2246 events).
5. **Status bar** now refreshes on the render timer (it was updated only at startup, so it read `0 net / 0 dns events` while bytes flowed) and reports `monitoring OFF (<source>)` when not live.
6. **Overview banner** `Live monitoring is off: <reason>` (amber, with the fix hint + engine.log path) instead of zeros; hidden when live.
7. New diagnostics: `outboundctl diag flows` — source, live flag, reason, counters, per-app totals and the top 12 flows with sent/recv, which is how the UI-vs-engine question was settled.

### Verification (elevated launch, `curl` 10 MB from speed.cloudflare.com — the user's `speed.hetzner.de` no longer resolves)
- engine.log: `ETW start: elevated=True` … `live monitoring started (ETW)`; `logman query -ets` shows both `OutboundWin-Net` and `OutboundWin-Dns` Running.
- `outboundctl diag flows`: `The curl executable … speed.cloudflare.com 172.66.0.218:443 Tcp sent=698 recv=10,020,919` — one flow, ~10 MB received (+0.2 % TLS/HTTP overhead), matching the reported `download=10000000` bytes.
- UI binding confirmed by instrumenting `RenderOverview` itself: `overview top-apps: flows=117 -> The curl executable=9.6 MB, Python=6.1 MB, …` (the card is fed from `_engine.Snapshot()`, i.e. the ETW totals — not the IP Helper snapshot). Instrumentation removed afterwards.

### Screenshot caveat (tooling, not the app)
After the PerMonitorV2 manifest, `PrintWindow(PW_RENDERFULLCONTENT)` returned flat frames and screen blits caught whatever window was on top (the Hermes app is in the foreground while I work). PerMonitorV2 was therefore **reverted** to the SDK default system-aware DPI (`<dpiAware>true</dpiAware>`); admin rights were the point of the manifest, and the WebView2 sizing problem it was meant to help had already been fixed by lazy-initialising the map page. The capture tool now detects a low-detail frame and falls back to a screen blit.

### UI binding — RESOLVED
The Overview card is fed from the ETW totals, confirmed twice by instrumenting `RenderOverview` itself:
`CARD flows=117 groups=17 -> [The curl executable]=9.6 MB, [Brave Browser]=42.7 KB, [Python]=39.5 KB, …`
with the same run showing `curlish=pid25984:The curl executable:recv10020067:speed.cloudflare.com`.
So `OvTopApps.ItemsSource` receives curl first with its ~10 MB (the app's own `_groups` Activity list shows it too).
My earlier "the card omits curl" reads came from scraping text over UIA, which is unreliable for a control that is
repainted every second — the card was right and the scraper was wrong. Instrumentation removed after the check.

### Final clean run (normal elevated launch, no flags)
- engine.log: `ETW start: elevated=True` → `stale sessions stopped before start: OutboundWin-Net, OutboundWin-Dns` → both sessions started → `live monitoring started (ETW)`.
- `curl` download reported 10,000,000 bytes → engine: `[app] The curl executable 10,021,092 (3 flows)`, totalRecv 10,123,554 (curl dominates), `source=etw live=True`, status bar `etw · N net / M dns events · elevated`.

## FIX: 2D map zoom snapped back (user report)

**Symptom:** zooming the 2D map worked, then the view jumped back to the fitted/world view each second.

**Cause:** `fitToData()` ran on every data push (~1/s). Its "user has moved the view" flag was set from
`dragstart`/`zoomstart` via a fragile `e.hardwareEvent !== false` check, which did not fire for a wheel
zoom — and even with the flag set, the rule *"re-fit if any destination lies outside the current view"*
re-framed on every push, undoing the zoom.

**Fix (web/map.js):**
- A user interaction is now detected as "a `zoomend`/`dragend` that did not come from us": our own moves
  go through `moveMap(fn)`, which sets a `programmatic` guard around `fitBounds`/`setView`. Wheel, drag,
  double-click and the +/− buttons all count; our auto-fit does not.
- `fitToData()` returns immediately when the user has taken over (`if (!force && userMoved) return;`) —
  the zoom is kept until the user asks for the framed view again.
- New **Fit** control on the map (bottom-right, next to +/−) calls `refitToData()`: clears the flag and
  reframes origin + destinations, so auto-fit resumes.
- Zoom headroom raised (`maxZoom 7 → 9`, `zoomSnap 0.25`, `wheelPxPerZoomLevel 90`) for smoother zooming.

**Verified** in the page's own self-test (needs no clicking):
`zoom: z0=1.25 afterProgrammatic=3.25 afterPush=3.25 programmaticDetectedAsUser=false` → `zoomSticks: OK`
— i.e. our programmatic fits are not mistaken for user moves, and after a user zoom a data push leaves the
view untouched. Build 0 errors.

**Note:** Leaflet applies wheel zoom asynchronously (~40 ms), so a synchronous assertion right after a
synthetic wheel event reads the old zoom — the test drives the same `moveMap`/`userMoved` path instead and
says so in a comment rather than pretending to test the gesture.

## Phase G1 — Window and backdrop — DONE (commit 1bcc0ff)
- `PickBackdrop()`: acrylic (Win11) → Mica (Win10) → `None`/solid when `HKCU\...\Personalize\EnableTransparency` is off. Midnight is always painted (no backdrop behind its navy gradient).
- Aurora: `GlowLayer` (radial blobs, oversized with -60 margin) + `AuroraDrift` storyboard (X 0→40 @ 60 s, Y 0→26 @ 90 s, auto-reverse, forever). Root panel stays transparent while a live backdrop is on so glass shows through.
- Crash handler: `DispatcherUnhandledException` + `AppDomain.UnhandledException` → `%LocalAppData%\OutboundWin\crash.log` + message box; app keeps running.
- Safe theme keys: `TryGetBrush()` + guarded `MergePalette()` — a missing palette file no longer crashes startup.
- Inter 4.1 static TTFs (Regular/Medium/SemiBold/Bold + OFL) bundled in `Fonts/Inter/`; `MahApps.Metro.IconPacks.Lucide` 6.2.1 added (verified net8.0-windows7.0). Nothing from Apple.
- User verified 2026-10-15. Build: 0 errors (2 fix cycles: `MessageBox` ambiguity vs WPF-UI import; Storyboard must target the `GlowLayer` element, not the transform object).

## Phase G2 — GlassCard style — DONE (commit dd05c14)
One reusable GlassCard style, applied everywhere (SPEC-GLASS §3). WPF can't blur what's behind a single element, so build glass from layers:
- **Fill:** vertical gradient — dark themes: white 14 % top → 6 % bottom; Light: white 70 % → 55 %.
- **Fake backdrop blur:** `VisualBrush` of the aurora layer with `BlurEffect` (radius ~40), aligned to the card position. Render once and cache (`BitmapCache`) — never blur live-changing content.
- **Specular edge:** 1 px border, diagonal gradient white 40 % top-left → 5 % bottom-right.
- **Inner top highlight:** 1 px line just inside the top edge, white 25 %, fading toward the sides.
- **Depth:** soft shadow (blur 30, opacity 0.3, offset 8) — cards only (DropShadowEffect is slow on many elements).
- **Shape:** radius 18 cards, 12 rows, capsule (h/2) for buttons/pills/search/segmented controls.
- **Apply to:** Overview stat card, Traffic card, Needs Review, Top Apps, inspector panel, sidebar, Ask prompt, approval dialog, tray flyout, compact Activity window.
- Every new brush/resource must exist in ALL four themes (Light, Graphite, Midnight, Aurora) or fall back safely (spec 0.4).
- After: build, launch normally, user OK → commit.
- Implemented: `Themes/Glass.xaml` defines `GlassCard`/`GlassRow`/`GlassPill` once; layers carried in one `GlassBackgroundBrush` DrawingBrush (aurora ImageBrush → fill gradient → top highlight) because a Border has no Template. Cached blurred aurora: `GlassState.BackdropImage` captured once on first ContentRendered (half-res RenderTargetBitmap + downscale = blur), published into each palette's `GlassAuroraBackdropBrush` ImageBrush, retained across palette swaps. Applied: MainWindow cards + sidebar, Ask prompt + segmented capsule, Approval rows, TrayFlyout card, Compact window (glass surface, SearchPill, rows, decision pill). All 5 glass keys × 4 themes.
- Build note: local SDK's WindowsDesktop ref pack is missing `DrawingContext.DrawVisual`/`PushEffect(Effect,Rect)` — avoid those APIs; use RenderTargetBitmap + DrawImage.
- User verified 2026-10-15. Build: 0 errors.

## Phase G3 — Floating capsule controls (NEXT)
Per SPEC-GLASS §4. Visual-only; same rules (build first, max 3 build-fix cycles, all new keys in all 4 themes).
- **Top bar (MainWindow):** status pill ("Protected · Ask mode") and the toolbar icon buttons become floating glass capsules — grouped icons inside one capsule (spec screenshots). New style `GlassToolbarCapsule` in `Themes/Glass.xaml`.
- **Segmented controls:** All / Allowed / Blocked, 2D / 3D, Learn / Ask / Strict. Glass capsule track (`GlassSegTrack` style) + brighter "liquid" selection pill (`GlassSegThumb`) that slides to the chosen option: ~250 ms, BackEase with slight overshoot. Slide = animate the thumb's `Margin` (or Canvas.Left) via a one-shot Storyboard fired on selection change; skip the animation when `SystemParameters.ClientAreaAnimation` is off.
- **Search boxes:** glass capsules with a Lucide magnifier icon (CompactWindow SearchPill already has the shape — finish icon + shared style).
- **Buttons:** glass by default (reuse `GlassPill` / capsule radius); primary actions get tinted glass — new per-theme keys `GlassPrimaryBrush` (accent at 35% + specular edge).
- **Allow / Block buttons:** tinted glass — new per-theme keys `GlassMintBrush` / `GlassCoralBrush` (mint/coral at 18%) with coloured icon + text.
- New resource keys (each in Light, Graphite, Midnight, Aurora): `GlassPrimaryBrush`, `GlassMintBrush`, `GlassCoralBrush` (+ any track/thumb brushes).
- Apply to: MainWindow top bar + all segmented controls + search, Ask/Approval/Compact buttons.
- After: build, close all Outbound.exe, launch normally, user OK → commit.
- **Done 2026-10-15 (part: segmented controls):** `GlassSegTrack` + `GlassSegThumb` in `Themes/Glass.xaml`; per-theme `GlassSegTrackBrush`/`GlassSegThumbBrush` in all 4 themes (no duplicate keys). Reusable `GlassSeg.SlideTo()` helper (`GlassSeg.cs`): ~250 ms BackEase (Amplitude 0.6) on the thumb's width + a `TranslateTransform.X`; instant jump when `SystemParameters.ClientAreaAnimation` is off or before first layout. Applied to the live **Learn/Ask/Strict** selector in `TrayFlyout` — 3-column equal-width grid, sliding thumb behind transparent `SegButton`s, wired via `SizeChanged` (instant) + click (animated). NOTE: All/Allowed/Blocked and 2D/3D groups do not exist as controls yet — the control is reusable and ready for them. Build: 0 errors (8 pre-existing warnings).
- **Done 2026-10-15 (part: tinted glass buttons + backdrop recapture):** Per-theme tinted keys in all 4 themes — `GlassPrimaryBrush` (accent 35→18% vertical fade), `GlassMintBrush` / `GlassCoralBrush` (mint/coral 20→12%), plus `GlassMintTextBrush` / `GlassCoralTextBrush` for tinted icon+text. Reusable styles in `Themes/Glass.xaml`: `GlassButtonBase` (BaseStyle on WPF default Button, rounded `CornerRadius 9`, ControlTemplate with pointer-over highlight layer + pressed opacity) and `GlassPrimaryButton` / `GlassMintButton` / `GlassCoralButton` (tinted Background via DynamicResource). Applied: AskWindow `BtnDeny` (coral, Ban icon) / `BtnAllow` (mint, Check icon) / `BtnAnswerAll` (primary); ApprovalWindow `BtnDeny` (coral) / `BtnApprove` (mint); CompactWindow decision pills (coral ✕ / mint ✓ chips); MainWindow `BtnApplyRules` (primary). Backdrop: `MainWindow` now re-captures the blurred aurora on window `SizeChanged` (180 ms debounce timer) and on `ThemeManager.Changed` (via Dispatcher at `Loaded`), so the blur stays crisp after resize and theme swap. Build: 0 errors (59 pre-existing warnings). App launched normally, user to verify.

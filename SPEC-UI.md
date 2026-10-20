# OutboundWin — UI spec (match the Mac app's look)

The user supplied four screenshots of Outbound for Mac (dark mode): **Network Monitor, Overview, All Rules, Review**. Save them as:
`G:\OutboundWin\reference\mac-monitor.png`, `mac-overview.png`, `mac-rules.png`, `mac-review.png`.
If your model can view images, open them. Either way, this file describes them in full. Build the Windows app to match this layout and feel. It's a redesign of the existing pages, not new features. Keep all existing logic.

Windows adaptation: no macOS traffic-light buttons. Use a WPF-UI `TitleBar` with minimize / maximize / close on the right, draggable, Mica backdrop. Everything else follows the screenshots. Dark theme is the main look; light theme must also work.

---

## 0. Map fixes (do first)

1. **Center on the user, not the USA.** The 2D map currently opens over the USA. On load and on every data refresh, fit the view to the origin plus all destinations (padding ~60 px). With no destinations yet, center on the origin at a regional zoom.
2. **Origin = this PC's location.** Settings › Location: a city picker (default Abu Dhabi, UAE), stored in settings. Draw the origin as a blue circle with a laptop icon (as in mac-monitor), with arcs starting from it.
3. **A real map, offline.** Replace the plain vector map with real imagery:
   - Bundle a public-domain Earth image (NASA Blue Marble or Natural Earth II shaded relief, ~8K px wide, JPG) as the base layer, plus Natural Earth country borders, coastlines and major city labels on top (vector, offline).
   - Use **MapLibre GL JS** (BSD licence) with the image as a raster source, or **Leaflet** with an image overlay. Zoom range: world → country level.
   - Styles (map style buttons, top-right of the map): **Satellite** (Blue Marble, default, darker ocean like the screenshot), **Standard** (Natural Earth relief, lighter), **Muted** (desaturated, dark).
   - The 3D globe uses the same Blue Marble texture (globe.gl `globeImageUrl`, bundled locally), with a night/dark-sky background.
   - No map tiles fetched from the internet. Everything ships in the app.

---

## 1. Window shell (all pages)

**Left sidebar** (~240 px, slightly lighter than the content, collapsible via a sidebar-toggle button at top):
- Top items with icons: **Overview**, **Network Monitor** (red badge = blocked count), **Analytics**, **Highlights**, **Assistant**.
- Section "Decisions": **Review** (count).
- Section "Rules": **All Rules**, **Allowed**, **Blocked**, **Recently Added**, **Recently Modified**, **Temporary**, **Disabled**, each with a count on the right.
- Section "Rule Groups" (checkbox per group, count on the right): **Windows services**, **Microsoft services**, **Microsoft apps**, **Apps you already have**, **Local network**.
- Section "Lists": **Blocklists** (count).
- Selected item: rounded highlight pill, bold text.
- Analytics / Highlights / Assistant can show a simple "Coming soon" page until Phase 9.

**Top bar**:
- Left: status pill with a green shield icon, "**Protected · Ask mode**" (amber if paused, grey if off). Clicking it opens a mode menu.
- Right: page-specific toolbar buttons, plus a **compact-mode** toggle and an **inspector** toggle (shows/hides the right panel).

---

## 2. Network Monitor (mac-monitor)

**Map area** (top ~45% of the content, rounded bottom edge, draggable splitter):
- Floating glass pill top-left: "? N without a location" with a dropdown listing those destinations.
- Floating segmented control top-right: **2D | 3D**, then map style buttons (icons), dropdown.
- Zoom **+ / −** and a compass (N) at bottom-right.
- Floating glass **stats card** at bottom-centre: **Apps** · **Places** · **Allowed** (green check) · **Blocked** (red x), big numbers with small labels.
- Arcs from the origin to each destination city: blue for allowed, red for blocked, glowing. Destination dots with city labels.

**Below the map**:
- Row: segmented **All | Allowed | Blocked**, time range dropdown (**1 Hour**, 5 min, 24 h, All), sort button.
- Search box "**Search apps and places**" with a filter icon (inserts scoped tokens), a record toggle button, and view toggles (chart / map).
- Summary line: "**11 apps · 29 destinations · 20 blocked**".
- Table header: **App / Destination** | **Traffic** | **Sent** | **Received** | **Last Seen** | (decision) | (actions).
- App rows: expand chevron, rounded app icon, bold app name; **Traffic** = a mini bar chart of ~12 bars (blue = received, orange cap = sent); Sent / Received in MB; Last Seen like "21 s", "6 min"; status text ("Asks", "Allowed", "Blocked"); a rounded pill with **✕** and **✓** buttons.
- Expanded app → destination rows (indented, favicon, host with main domain bold, port·proto, flag + city).

**Inspector** (right panel, ~360 px, toggleable):
- Header: large rounded icon (favicon of the host, or app icon), **host** in bold, "443 · TCP" below.
- App line: app icon + name; right side "Rules now: Waiting" (amber dot) or "Allowed"/"Blocked", and "Last time: Allowed".
- **WHY**: plain sentence, e.g. "No rule covers this. Ask mode allowed it and recorded it for review." or "Denied by your rule for doubleclick.net." Small grey line: "Evaluated against the rules the filter enforces."
- **EXPLAIN**: link "Explain with AI" (wired in Phase 9; disabled until then).
- **CHANGE IT**: three blue links with icons: "Allow <host> for <app>", "Block <host> for <app>", "Block *.<domain> for every app". Each creates the rule immediately (same rule path as the CLI).
- **CONNECTION DETAILS** (collapsible): Host, Service, Last address, Port, Protocol, Direction, Allowed, Blocked, First seen, Last seen, Last allowed, Last blocked.
- **GEOGRAPHIC INFORMATION** (collapsible): City, Region, Country (blue, as links that filter the list).

---

## 3. Overview (mac-overview)

- Header: large green shield with check, title "**Protected**" (big, bold), subtitle "**Ask mode · 11 rules · 2 blocklists**". Right: blue button "**Review N Connections**" (goes to Review).
- "**Last hour**" card: five stats separated by thin dividers: **Apps online**, **Connections**, **Blocked**, **↑ Sent** (orange arrow), **↓ Received** (blue arrow). Big numbers.
- "**Traffic**" card, subtitle "Peak 89 KB/s received at 8:40 AM", link "**Open Monitor**" at right. Smooth area chart: received = blue line with a translucent blue fill, sent = orange line, y-axis in KB/s, time labels, legend "● Sent ● Received". Hover shows a tooltip with time + rates.
- Two cards side by side:
  - "**Needs Review**": rows with app icon, app name, "files.slack.com and 1 more", and tinted buttons **✓ Allow** (green) and **⊘ Block** (red).
  - "**Top Apps**" with "**See All**" link: rank number, app icon, name, a thin two-tone bar (orange sent, blue received), total MB.

---

## 4. All Rules (mac-rules)

- Toolbar right: suggestions (lightbulb), AI (sparkle, disabled until Phase 9), import/export dropdown, **+** (new rule).
- Search box "**Apps, hosts, ports**".
- Header: **Process** | **Rule**.
- Rules grouped by app: first row of a group shows the app icon + name (grey sub-line "Not installed · <path>" when the app isn't present); following rows of the same app are indented under it. Alternating subtle row backgrounds per group.
- Each rule row: **enabled checkbox**, decision icon (**green ✓ allow**, **red ✕ block**, **orange ? ask**), destination favicon or globe icon, the rule as a sentence in lower case style: "allow domain git.corp.example port 443 TCP", "block any connection TCP".
- Right-side tags (rounded, outlined): profile ("**Office**", "**Home**"), "**Blocklist: <name>**" with a **lock** icon (read-only), lifetime ("**Until Oct 12, 2026 at 3:31 PM**", "**Until quit**").
- Disabled rules shown greyed out.
- Footer note: "Host and domain rules need a hostname reported by Windows. Direct IP connections need an address or network rule."
- Sidebar filters (Allowed, Blocked, Recently Added, Recently Modified, Temporary, Disabled) show this same list filtered.

---

## 5. Review (mac-review)

- Row: segmented **All | Allowed | Blocked**, then grey text "**Decided without asking you. Make a rule, or dismiss.**", and at the right "**10 of 10 · 4 apps**".
- Toolbar right: "Allow verified publishers" button and "Review all" button.
- App rows: chevron, app icon, bold name, sub-line "**2 destinations · all allowed**" / "all blocked", a count badge, and a **✕ / ✓** pill at the right. Expanding shows each destination with its own ✕ / ✓.

---

## 6. Look & motion

- Rounded corners (8–12 px), soft cards slightly lighter than the background, thin dividers, generous padding. Font: Segoe UI Variable. Accent blue, green for allowed, red for blocked, orange for sent/ask.
- **Animations** (subtle, 150–300 ms, ease-out):
  - Page switches: quick fade + slight slide.
  - Numbers count up when they change; new table rows fade in; rows briefly highlight when their traffic updates.
  - Sidebar selection pill slides between items.
  - Map: arcs draw in from the origin; small "packets" glide along active arcs; destination dots pulse on new connections; new-city pop-up label springs in and fades.
  - Buttons: hover and press states. Inspector slides in/out.
- Real app icons everywhere (exe icon extraction), website favicons in host rows (cached locally; switch to turn off in Settings).

---

## Done means

Launched normally (no flags). The user checks each page against the Mac screenshot and confirms. PrintWindow can't capture the WebView2 map, so the map is confirmed by the user. Work page by page in this order: map fixes → shell → Network Monitor → Overview → All Rules → Review → motion polish. Ask the user to look after each page.

# OutboundWin — Glass UI spec (Apple "Liquid Glass" look on Windows)

Goal: give OutboundWin the frosted, layered "glass" look of Apple's current design (translucent panels, light catching the edges, floating capsule controls, soft motion), built with Windows-native and freely licensed parts. Keep all existing features and logic. This is a visual layer on top of the current pages and the Aurora theme.

Read with SPEC-UI.md and PROGRESS.md. Work in the phases below. After each phase: build, launch Outbound.exe normally (elevated, no flags), ask the user to look, wait for OK, then **git commit**.

---

## 0. Safety first (before any visual work)

1. Make sure the project is a git repo. If not: `git init`, add a .gitignore for bin/obj, commit the current working state as "baseline before glass".
2. Commit after every phase that the user approves. If a phase breaks the app, `git restore`/revert to the last commit instead of debugging for hours.
3. Global crash handler must exist (DispatcherUnhandledException + AppDomain.UnhandledException → %LocalAppData%\OutboundWin\crash.log + message box).
4. Every new style/brush resource must exist in ALL themes (Light, Dark, Midnight, Aurora) or fall back safely. A missing key must never crash startup.

---

## 1. What to download, and from where (licences matter)

Allowed (free to bundle):
- **Font: Inter** (closest free match to Apple's SF Pro). Source: https://github.com/rsms/inter/releases. Licence SIL OFL 1.1. Use the **static** TTF files (Regular, Medium, SemiBold, Bold), not the variable font (WPF handles variable fonts poorly). Keep Plus Jakarta Sans for the Aurora theme if already done. Add an option in Appearance: Font = Inter / Plus Jakarta Sans.
- **Mono font: JetBrains Mono** (already used): https://github.com/JetBrains/JetBrainsMono/releases, OFL.
- **Icons (thin, SF-Symbols-like look): Lucide**, licence ISC. Easiest in WPF via the NuGet package **MahApps.Metro.IconPacks.Lucide** (MIT; verify the package name on nuget.org and that it targets net8.0-windows). Alternative: keep WPF-UI's Fluent System Icons (already bundled). Use one icon family consistently.
- **Glass helpers:** WPF-UI (lepoco/wpfui, already used) for Mica / Acrylic window backdrops.

NOT allowed — do not download or bundle:
- Apple's **SF Pro** fonts, **SF Symbols**, Apple wallpapers, Apple Design Resources (Figma/Sketch kits). Their licences only allow use for Apple platforms.
- Use Apple's Human Interface Guidelines (developer.apple.com/design/human-interface-guidelines/materials) only as a description of the idea, never as a source of assets.

Backgrounds: generate them in code (gradients/blobs), don't download images, so there are no licence questions.

---

## 2. Phase G1 — Window and backdrop

- Main window: WPF-UI `FluentWindow` with `WindowBackdropType="Acrylic"` for the sidebar feel (fall back to `Mica`, then to a solid colour on Windows 10).
- Behind the content, a theme "aurora" layer: 2–3 large soft colour blobs (radial gradients, Aurora palette) at low opacity, very slowly drifting (60–90 s loop). This is what the glass panels sit on and "see through".
- Respect Windows **Settings › Personalisation › Colours › Transparency effects** (registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\EnableTransparency`). If off: no blur, solid backgrounds. Also add an app setting "Reduce transparency".

## 3. Phase G2 — The GlassCard style (one reusable style, used everywhere)

WPF can't blur what's behind a single element, so build glass from layers:
- **Fill:** vertical gradient, white 14% at top → white 6% at bottom (dark themes); for Light theme use white 70% → 55%.
- **Fake backdrop blur:** because the window background is known (the aurora layer), give each card a `VisualBrush` of the aurora layer with a `BlurEffect` (radius ~40), aligned to the card's position. Render it once and cache (`RenderOptions.CachingHint`, `BitmapCache`) — never blur live-changing content.
- **Specular edge (the "glass" highlight):** 1 px border with a diagonal gradient, white 40% top-left → white 5% bottom-right.
- **Inner top highlight:** a 1 px line just inside the top edge, white 25%, fading out toward the sides.
- **Depth:** soft shadow below the card (blur 30, opacity 0.3, offset 8). DropShadowEffect is slow on many elements — use it on cards only, or a pre-rendered shadow border.
- **Shape:** corner radius 18 for cards, 12 for rows, full capsule (radius = height / 2) for buttons, pills, search boxes and segmented controls.
- Apply GlassCard to: Overview stat card, Traffic card, Needs Review, Top Apps, inspector panel, sidebar, Ask prompt, approval dialog, tray flyout, compact Activity window.

## 4. Phase G3 — Floating capsule controls

- Top bar: status pill ("Protected · Ask mode") and toolbar buttons become floating glass capsules (grouped icons in one capsule, like the Mac screenshots).
- **Segmented controls** (All / Allowed / Blocked, 2D / 3D, Learn / Ask / Strict): glass capsule track with a brighter "liquid" selection pill that slides to the chosen option with a slight overshoot (BackEase, ~250 ms).
- Search boxes: glass capsules with a magnifier icon.
- Buttons: glass by default; primary actions get a tinted glass (accent colour at 35% + specular edge).
- Allow / Block buttons: tinted glass (mint / coral at 18%) with coloured icon and text.

## 5. Phase G4 — Motion

- Hover: card fill +4%, highlight edge brighter, scale 1.01 (120 ms). Press: scale 0.98.
- Page change: fade + 12 px slide (220 ms, ease-out).
- Sidebar selection pill slides between items (spring-like BackEase).
- Numbers count up when they change; new rows fade/slide in.
- Popups (Ask prompt, flyout, menus) open with scale 0.96 → 1 + fade (180 ms).
- Respect Windows "Animation effects" off (SystemParameters.ClientAreaAnimation) → no motion.

## 6. Phase G5 — Map overlays (WebView2, real glass is possible here)

Refine the HTML overlays to true glass:
- `background: rgba(22,26,43,0.45); backdrop-filter: blur(24px) saturate(180%);`
- Border: 1 px gradient (white 35% → 5%) via a pseudo-element mask; `box-shadow: inset 0 1px 0 rgba(255,255,255,0.25), 0 10px 30px rgba(0,0,0,0.35);`
- Capsule shapes for the 2D/3D switch, style buttons and zoom; stats card radius 18.

## 7. Phase G6 — Performance and check

- Measure CPU and GPU with the app idle and with the Network Monitor open (Task Manager). Target: idle CPU under ~2 %, smooth scrolling. If glass costs too much, reduce: fewer shadows, cache blurred brushes, lower blob animation rate.
- Test all four themes and both Transparency on/off.
- User checks every page; commit.

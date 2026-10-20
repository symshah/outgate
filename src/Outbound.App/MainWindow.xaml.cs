using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Outbound.Core.Engine;
using Outbound.Core.Enforcement;
using Outbound.Core.Identity;
using Outbound.Core.Network;
using Outbound.Core.Policy;
using Outbound.Core.Rules;
using Outbound.Core.Store;
using Microsoft.Web.WebView2.Core;
using ScottPlot;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;
using MessageBox = System.Windows.MessageBox;

namespace Outbound.App;

public partial class MainWindow : FluentWindow
{
    private readonly OutboundEngine _engine;
    private readonly PolicyService _policy;
    private readonly RuleStore _store;
    private readonly System.Windows.Threading.DispatcherTimer _refresh;

    public ObservableCollection<AppGroupVm> Apps { get; } = [];
    public ObservableCollection<RuleRowVm> Rules { get; } = [];
    public ObservableCollection<ReviewRowVm> Review { get; } = [];

    // Activity page filter state (SPEC Phase 3: smart tokens + time range)
    private readonly Dictionary<string, DateTime> _appFirstSeen = new();   // app key → first flow seen this session ("new apps")
    private readonly Dictionary<string, ImageSource?> _iconCache = new();  // exe path → icon
    private static readonly string[] AiApps = { "openai", "chatgpt", "claude", "anthropic", "gemini", "google.ai", "copilot", "bingservice", "perplexity", "mistral", "llm", "lmstudio", "ollama", "whisper" };
    private static readonly string[] AdHosts = { "doubleclick.net", "googlesyndication.com", "adsystem", "adserver", "taboola.com", "outbrain.com", "criteo.com", "amazon-adsystem.com", "moatads.com", "scorecardresearch.com", "quantserve.com", "mopub.com", "applovin.com", "unity3d.com", "adjust.com", "amplitude.com", "mixpanel.com", "segment.io", "hotjar.com", "clarity.ms", "facebook.net", "fbcdn.net" };
    private static readonly string[] MsServices = { "windowsupdate", "wuauserv", "svchost", "microsoftedge", "msedge", "teams.exe", "onedrive", "skype", "office", "outlook", "winstore", "store", "xbox", "gamebar", "searchindexer", "diagnosticshub", "connecteduser", "wisvc" };

    private DateTime _lastRender = DateTime.MinValue;

    // Phase 4: offline map/globe host + push state
    private CoreWebView2? _mapWebCore;   // CoreWebView2 once initialized (null if runtime missing)
    private bool _mapReady;             // page loaded, safe to post messages
    private long _lastMapPush = 0;      // UTC ticks of last map payload sent
    private bool _mapSelfTested;        // one-shot: run JS self-test on first data-rich push
    private IpcServer? _ipc;            // Phase 5: named-pipe server for outboundctl / MCP

    /// <summary>Exposed for the tray flyout (Phase 3 item 2).</summary>
    public OutboundEngine Engine => _engine;
    public PolicyService Policy => _policy;

    // Phase 5 IPC: members the pipe server reads.
    private readonly string _rulesDbPath;
    public string RulesDbPath => _rulesDbPath;
    public DateTime StartedUtc { get; } = DateTime.UtcNow;
    public int FlowCount() => _engine.Snapshot().Count;

    /// <summary>"Open Outbound" from the tray: restore + activate the main window.</summary>
    public void ShowFromTray()
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (!IsVisible) Show();
            WindowState = WindowState.Normal;
            Activate();
            Topmost = true;
            Topmost = false;
        });
    }

    public MainWindow()
    {
        InitializeComponent();
        string dbPath = Environment.GetEnvironmentVariable("OUTBOUND_RULES") ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "rules.db");
        _rulesDbPath = dbPath;

        _store = new RuleStore(dbPath);
        _engine = new OutboundEngine(dbPath);
        _policy = new PolicyService(dbPath);
        try { _engine.Start(); StatusText.Text = $"Monitoring live ({_engine.Source})"; }
        catch (Exception ex) { StatusText.Text = $"Monitoring unavailable: {ex.Message}"; }
        _policy.Attach(_engine); // evaluates + records every flow (trust-aware) — the single evaluation point
        // Phase 5: toasts (blocked / new country) → tray balloon, marshalled onto the UI thread.
        _policy.Toasts.Toast += (title, msg) => Dispatcher.BeginInvoke(() =>
        {
            try { ((App)Application.Current).Tray?.ShowNotification(title, msg, H.NotifyIcon.Core.NotificationIcon.Warning); }
            catch { /* toast display is best-effort */ }
        });
        // Profiles/blocklists mutate from background threads (watcher, fetches) — marshal UI refresh to the dispatcher.
        _policy.Profiles.Changed += (_, _) => Dispatcher.BeginInvoke(RefreshProfilesUi);
        _policy.Blocklists.Changed += () => Dispatcher.BeginInvoke(RefreshBlocklistsUi);
        _policy.Limits.Changed += () => Dispatcher.BeginInvoke(RefreshLimitsUi);
        Task.Run(async () => await _policy.Blocklists.LoadAndFetchAsync()); // re-fetch persisted lists at startup (best effort)

        RulesGrid.ItemsSource = Rules;
        ReviewGrid.ItemsSource = Review;
        ActivityList.ItemsSource = Apps;
        ActivityList.SelectionChanged += (_, _) => UpdateInspector();

        // Navigation: NavList (ListBox) selection drives the visible page — wired in XAML
        // (NavList_SelectionChanged). WPF-UI 4.0's NavigationViewItem never exposed
        // Invoke/SelectionItem, so the rail is a ListBox: real UIA selection + arrow keys.

        // Keyboard access: Ctrl+1..Ctrl+6 switch pages (Overview, Activity, Rules, Review, Map, Settings).
        PreviewKeyDown += OnNavShortcut;

        // Activity page: search box (free text + smart tokens), token checkboxes, time-range picker.
        TxtSearch.TextChanged += (_, _) => { SyncTokensFromText(); ApplyActivityFilter(); };
        var tokenBoxes = new[] { TokAi, TokAds, TokNew, TokUnsigned, TokMicrosoft, TokLocal, TokAbroad, TokHeavy };
        foreach (var cb in tokenBoxes)
        {
            cb.Checked += (_, _) => { SyncTextFromTokens(); ApplyActivityFilter(); };
            cb.Unchecked += (_, _) => { SyncTextFromTokens(); ApplyActivityFilter(); };
        }
        CmbRange.SelectionChanged += (_, _) => ApplyActivityFilter();

        _refresh = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        // Also refresh the status bar (monitoring source, ETW counters) — it used to freeze at the
        // startup values, so it showed "0 net / 0 dns events" even while bytes were flowing.
        _refresh.Tick += (_, _) => { Render(); UpdateStatus(); };
        _refresh.Start();

        // Phase 4 map/globe is created lazily, the first time the Map page is actually shown:
        // initialising it while PageMap is Collapsed gives the control a 0x0 layout size, and
        // the page then renders at WebView2's default viewport — the top-places list and the
        // traffic chart end up outside the visible area.
        _ipc = new IpcServer(this); // Phase 5: named-pipe server for outboundctl / MCP

        Loaded += (_, _) =>
        {
            // Startup mode override (--mode ask|learn|strict) beats the persisted setting.
            if (App.StartupMode is string m && Enum.TryParse<Outbound.Core.Policy.Mode>(m, true, out var mm))
                _policy.Engine.Settings.Mode = mm;
            LoadSettingsUi();
            RefreshRules(); RefreshReview(); UpdateStatus();
            // --page override (used by tests and the Phase 5 CLI); default Overview.
            var sp = App.StartupPage;
            var startPage = sp is "activity" or "rules" or "review" or "map" or "settings" ? sp : "overview";
            // ShowPage syncs the NavList selection itself.
            ShowPage(startPage);
            ((App)Application.Current).Flyout?.Wire(this);
            NameCaptionButtons();
            ThemeManager.Apply(ThemeManager.Current, this); // window chrome for the persisted theme (gradient + 1px border on Midnight)
            UpdateThemeButtons();
            // SPEC-GLASS G1: start the slow aurora drift (X 60s / Y 90s, auto-reversing).
            if (FindResource("AuroraDrift") is System.Windows.Media.Animation.Storyboard drift)
                drift.Begin();
        };
        // SPEC-GLASS G2: one-shot capture of the aurora glow as the glass cards' backdrop.
        bool glassCaptured = false;
        ContentRendered += (_, _) =>
        {
            if (glassCaptured) return;
            glassCaptured = true;
            Dispatcher.BeginInvoke(CaptureGlassBackdrop, System.Windows.Threading.DispatcherPriority.Loaded);
        };

        // SPEC-GLASS G2: render the glow layer to a half-res bitmap, blur it, publish as
        // GlassAuroraBackdropBrush (the cached blurred aurora layer of every glass card).
        void CaptureGlassBackdrop()
        {
            try
            {
                var glow = GlowLayer;
                if (glow == null || glow.ActualWidth < 8 || glow.ActualHeight < 8) return;
                int w = (int)(glow.ActualWidth / 2);
                int h = (int)(glow.ActualHeight / 2);
                var full = new RenderTargetBitmap((int)glow.ActualWidth, (int)glow.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                full.Render(glow);
                full.Freeze();
                var dst = new DrawingVisual();
                using (var dc = dst.RenderOpen())
                    dc.DrawImage(full, new Rect(0, 0, w, h));
                var outBmp = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
                outBmp.Render(dst);
                outBmp.Freeze();
                GlassState.BackdropImage = outBmp;
                foreach (var dict in Application.Current.Resources.MergedDictionaries)
                    if (dict.Contains("GlassAuroraBackdropBrush"))
                    {
                        if (dict["GlassAuroraBackdropBrush"] is System.Windows.Media.ImageBrush ib)
                            ib.ImageSource = outBmp;
                        else
                            dict["GlassAuroraBackdropBrush"] = new System.Windows.Media.ImageBrush { ImageSource = outBmp, Stretch = System.Windows.Media.Stretch.Fill };
                    }
            }
            catch { /* visual-only: a failed backdrop capture must never break startup */ }
        }
        // SPEC-GLASS G3: keep the blurred aurora backdrop in sync — re-capture on window
        // resize (debounced) and on theme change (the glow's DynamicResource brushes re-skin).
        var _backdropDebounce = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(180) };
        _backdropDebounce.Tick += (_, _) => { _backdropDebounce.Stop(); CaptureGlassBackdrop(); };
        SizeChanged += (_, _) => { _backdropDebounce.Stop(); _backdropDebounce.Start(); };
        ThemeManager.Changed += () => Dispatcher.BeginInvoke(CaptureGlassBackdrop, System.Windows.Threading.DispatcherPriority.Loaded);
        Closing += (_, _) => { _refresh.Stop(); try { MapWeb.Dispose(); } catch { /* already disposed */ } _ipc?.Dispose(); _engine.Dispose(); _policy.Dispose(); _store.Dispose(); };

        // Ask prompt window (Phase 3 item 3): open on new prompts, refresh when one resolves.
        void PumpAsk() => Dispatcher.BeginInvoke(() => ((App)Application.Current).EnsureAsk(_policy)?.Refresh());
        _policy.Prompts.NewPrompt += _ => PumpAsk();
        _policy.Prompts.Resolved += _ => PumpAsk();
        _policy.Prompts.TimeoutDecision += (_, _) => PumpAsk();

        BtnRefresh.Click += (_, _) => { Render(); UpdateStatus(" · refreshed"); };
        BtnAddRule.Click += (_, _) => AddRuleFromForm();
        BtnDeleteRule.Click += (_, _) => DeleteSelectedRule();
        BtnApplyRules.Click += (_, _) => ApplyRules();
        BtnClearRules.Click += (_, _) => ClearFirewallRules();
        BtnThemeToggle.Click += (_, _) => ToggleTheme();
        BtnThemeToggle2.Click += (_, _) => ToggleTheme();
        BtnCompact.Click += (_, _) => ToggleCompact();
        BtnHelp.Click += (_, _) => new HelpWindow(this) { Owner = this }.Show();
        UpdateThemeButtons();
    }

    // ---------- Navigation (Phase 3 item 4): left nav, six sections ----------

    // WPF-UI 4.0 nav items exposed no UIA patterns at all — NavList (ListBox) replaces them.
    private static readonly string[] NavPages = { "overview", "activity", "rules", "review", "map", "settings" };
    private bool _navSyncing; // true while ShowPage updates the rail selection (avoids re-entrant SelectionChanged)

    private bool _mapInitStarted; // WebView2 is created on first Map show, never at startup

    /// <summary>
    /// Wpf.Ui's TitleBar template buttons have no accessible name, so Narrator announces three
    /// anonymous buttons in a row. Name them from the template parts once the template is applied.
    /// </summary>
    private void NameCaptionButtons()
    {
        try
        {
            TitleBarCtl.ApplyTemplate();
            var parts = new (string Part, string Name)[]
            {
                ("PART_MinimizeButton", "Minimize"),
                ("PART_MaximizeButton", "Maximize"),
                ("PART_RestoreButton", "Restore"),
                ("PART_CloseButton", "Close"),
            };
            foreach (var (part, name) in parts)
                if (TitleBarCtl.Template?.FindName(part, TitleBarCtl) is DependencyObject el)
                    System.Windows.Automation.AutomationProperties.SetName(el, name);
        }
        catch { /* naming is best-effort — never block startup for it */ }
    }

    /// <summary>
    /// Create the Map page's WebView2 the first time the page is shown, after it has been laid
    /// out. A WebView2 created while its container is Collapsed gets a 0x0 layout size and lays
    /// the HTML out at WebView2's default viewport, so the top-places list and traffic chart
    /// land outside the visible area.
    /// </summary>
    private void ShowMapPage()
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (!_mapInitStarted) { _mapInitStarted = true; InitMapWeb(); }
            else { try { MapWeb.UpdateLayout(); } catch { /* resize is handled by the control */ } }
        }, System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void NavList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_navSyncing) return;
        if (NavList.SelectedItem is ListBoxItem item && item.Tag is string tag) ShowPage(tag);
    }

    private void ShowPage(string page)
    {
        PageOverview.Visibility = page == "overview" ? Visibility.Visible : Visibility.Collapsed;
        PageActivity.Visibility = page == "activity" ? Visibility.Visible : Visibility.Collapsed;
        PageRules.Visibility = page == "rules" ? Visibility.Visible : Visibility.Collapsed;
        PageReview.Visibility = page == "review" ? Visibility.Visible : Visibility.Collapsed;
        PageMap.Visibility = page == "map" ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = page == "settings" ? Visibility.Visible : Visibility.Collapsed;
        // Keep the nav rail selection in sync with the visible page.
        int navIdx = Array.IndexOf(NavPages, page);
        if (navIdx >= 0 && NavList.SelectedIndex != navIdx)
        {
            _navSyncing = true;
            try { NavList.SelectedIndex = navIdx; } finally { _navSyncing = false; }
        }
        if (page == "overview") RenderOverview();
        if (page == "activity") UpdateInspector();
        if (page == "review") RefreshReview();
        if (page == "settings") { LoadProfilesUi(); LoadBlocklistsUi(); LoadLimitsUi(); }
        if (page == "map") ShowMapPage();
    }

    /// <summary>Automation entry point for the IPC `ui.show` command — switches the visible page (UI thread).</summary>
    internal void ShowPageForAutomation(string page) => ShowPage(page);

    // Ctrl+1..Ctrl+6 → Overview, Activity, Rules, Review, Map, Settings.
    private void OnNavShortcut(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.KeyboardDevice.Modifiers != System.Windows.Input.ModifierKeys.Control) return;
        string? page = e.Key switch
        {
            System.Windows.Input.Key.D1 => "overview",
            System.Windows.Input.Key.D2 => "activity",
            System.Windows.Input.Key.D3 => "rules",
            System.Windows.Input.Key.D4 => "review",
            System.Windows.Input.Key.D5 => "map",
            System.Windows.Input.Key.D6 => "settings",
            _ => null,
        };
        if (page != null) { ShowPage(page); e.Handled = true; }
    }

    // ---------- Live rendering ----------

    private readonly Dictionary<string, AppGroupVm> _groups = new(); // app key → persistent group (survives list rebuilds)

    private void Render()
    {
        var now = DateTime.UtcNow;
        if (now - _lastRender < TimeSpan.FromMilliseconds(500)) return;
        _lastRender = now;
        Dispatcher.BeginInvoke(() =>
        {
            var flows = _engine.Snapshot();
            foreach (var f in flows)
                if (!_appFirstSeen.ContainsKey(f.App.Key))
                    _appFirstSeen[f.App.Key] = now;

            // Update persistent app groups (get-or-create, so sparklines/icons survive refreshes).
            var seen = new HashSet<string>();
            foreach (var g in flows.GroupBy(f => f.App.Key))
            {
                var list = g.ToList();
                seen.Add(g.Key);
                if (!_groups.TryGetValue(g.Key, out var grp))
                {
                    var first = list[0];
                    grp = new AppGroupVm
                    {
                        Key = g.Key, Name = first.App.DisplayName, ExePath = first.App.ExePath,
                        SignerKind = first.App.Signer.Kind, Icon = LoadAppIcon(first.App.ExePath),
                    };
                    _groups[g.Key] = grp;
                }
                UpdateGroup(grp, list, now);
            }
            foreach (var gone in _groups.Where(kv => !seen.Contains(kv.Key)).Select(kv => kv.Value).ToList())
                _groups.Remove(gone.Key);

            FlowCountText.Text = $"{flows.Count} flows · {ModeNames.Of(_policy.Engine.Settings.Mode)}";
            StatusPill.Text = $"Protected · {ModeNames.Of(_policy.Engine.Settings.Mode)} mode"; // SPEC-GLASS G3: live status pill
            ApplyActivityFilter();
            if (PageOverview.Visibility == Visibility.Visible) RenderOverview();
            if (PageMap.Visibility == Visibility.Visible) PushMapData(now); // Phase 4: live map/globe data
        });
    }

    // ---------- Phase 4: offline map/globe (WebView2, bundled d3-geo + world-atlas + globe.gl) ----------

    private async void InitMapWeb()
    {
        try
        {
            string userData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "webview2");
            Directory.CreateDirectory(userData);
            var env = await CoreWebView2Environment.CreateAsync(null, userData);
            await MapWeb.EnsureCoreWebView2Async(env);
            _mapWebCore = MapWeb.CoreWebView2;
            _mapWebCore.Settings.AreDefaultContextMenusEnabled = false;
            _mapWebCore.Settings.IsStatusBarEnabled = false;
            // Serve bundled assets via a virtual host so fetch/XHR work (file:// is blocked).
            _mapWebCore.SetVirtualHostNameToFolderMapping(
                "appassets", Path.Combine(AppContext.BaseDirectory, "web"), CoreWebView2HostResourceAccessKind.Allow);
            _mapWebCore.NavigationCompleted += async (_, _) => {
                _mapReady = true; MapDebug("nav-completed");
                var dpi = VisualTreeHelper.GetDpi(this);
                MapDebug($"sizes: window={ActualWidth:F0}x{ActualHeight:F0} dip, dpiScale={dpi.DpiScaleX:F2}, mapCtl={MapWeb.ActualWidth:F0}x{MapWeb.ActualHeight:F0} dip, pageVisible={PageMap.Visibility}");
                try { MapDebug("probe: " + await _mapWebCore.ExecuteScriptAsync(
                    "JSON.stringify({push: typeof window.__push, d3keys: Object.keys(window.d3||{}).slice(0,12), natE: typeof (window.d3&&d3.geoNaturalEarth1), leaflet: (typeof L!=='undefined') ? L.version : 'none', raster: (function(){var i=document.querySelector('#viz .leaflet-image-layer'); return i ? (i.complete && i.naturalWidth>0 ? 'loaded '+i.naturalWidth+'x'+i.naturalHeight : 'NOT-LOADED') : 'none';})(), tipChild: !!(document.getElementById('tip')&&document.getElementById('tip').parentElement), innerW: innerWidth, innerH: innerHeight, dpr: devicePixelRatio, sideW: document.getElementById('side') ? Math.round(document.getElementById('side').getBoundingClientRect().width) : -1, chartH: document.getElementById('chartwrap') ? Math.round(document.getElementById('chartwrap').getBoundingClientRect().height) : -1, box: (function(){ function r(id){ var e=document.getElementById(id); if(!e) return id+':none'; var b=e.getBoundingClientRect(); var cs=getComputedStyle(e); return id+':x'+Math.round(b.x)+' y'+Math.round(b.y)+' w'+Math.round(b.width)+' h'+Math.round(b.height)+' d'+cs.display+' v'+cs.visibility; } return [r('top'),r('main'),r('viz'),r('side'),r('chartwrap'),r('places')].join(' | '); })()})")); } catch (Exception ex) { MapDebug("probe-failed: " + ex.Message); }
            };
            _mapWebCore.DocumentTitleChanged += (_, _) => MapDebug("title: " + _mapWebCore.DocumentTitle);
            _mapWebCore.Navigate("https://appassets/map.html"); // virtual host → bundled web\ folder
        }
        catch (Exception ex)
        {
            MapDebug("init-failed: " + ex.Message);
            MapFallback.Visibility = Visibility.Visible; // no WebView2 runtime on this machine
        }
    }

    private static void MapDebug(string msg)
    {
        try { File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "map-debug.log"), $"{DateTime.Now:HH:mm:ss.fff} {msg}\n"); } catch { }
    }

    private (double lat, double lon)? _mapOrigin;

    /// <summary>Compact Activity: one row per destination, newest first (SPEC-UI §2).</summary>
    // ---------- Compact Activity feed (SPEC-UI §2 compact window) ----------

    private CompactWindow? _compact;

    /// <summary>Open (or focus) the compact live Activity window.</summary>
    public void ToggleCompact()
    {
        if (_compact is { IsVisible: true })
        {
            _compact.Activate();
            return;
        }
        var w = new CompactWindow(this);
        _compact = w;
        w.Closed += (_, _) => { if (ReferenceEquals(_compact, w)) _compact = null; };
        w.Show();
    }

    /// <summary>Live rows for the compact feed: one per destination, newest first.</summary>
    public List<CompactRowVm> BuildCompactRows(int max)
    {
        var rows = new List<CompactRowVm>();
        var pending = _policy.Prompts.All();   // asks currently waiting for an answer
        foreach (var grp in _groups.Values)
        {
            foreach (var d in grp.AllDests.Values)
            {
                bool waiting = false;
                foreach (var ask in pending)
                {
                    var c = ask.Ctx;
                    if (c.RemotePort != d.Port) continue;
                    if (!string.Equals(c.RemoteIp ?? "", d.RemoteIp, StringComparison.OrdinalIgnoreCase)) continue;
                    if (!string.IsNullOrEmpty(c.Host) && !string.Equals(c.Host, d.Host, StringComparison.OrdinalIgnoreCase)) continue;
                    waiting = true;
                    break;
                }
                string cc = d.GeoCc ?? "";
                rows.Add(new CompactRowVm
                {
                    Key = grp.Key + "|" + d.FlowKey,
                    AppName = grp.Name,
                    ExePath = grp.ExePath ?? "",
                    Icon = grp.Icon,
                    Host = string.IsNullOrEmpty(d.Host) ? d.RemoteIp : d.Host,
                    Domain = d.Domain,
                    Port = d.Port,
                    Proto = d.Proto,
                    CountryCity = (cc.Length > 0 ? cc.ToUpperInvariant() + " " : "") + (d.GeoCity ?? ""),
                    IsLocal = d.IsLocal,
                    Ago = AgoText(d.LastSeenUtc),
                    BytesDisplay = d.BytesDisplay,
                    Decision = waiting ? CompactDecision.Waiting : (d.DecisionIsDeny ? CompactDecision.Blocked : CompactDecision.Allowed),
                    SortUtc = d.LastSeenUtc,
                });
            }
        }
        LastCompactTotal = rows.Count; // true count; the feed itself is capped for speed
        return rows.OrderByDescending(r => r.SortUtc).Take(max).ToList();
    }

    /// <summary>Distinct destinations in the last compact-feed build (uncapped) — the "N seen today" figure.</summary>
    public int LastCompactTotal { get; private set; }

    private static string AgoText(DateTime lastUtc)
    {
        double s = (DateTime.UtcNow - lastUtc).TotalSeconds;
        if (s < 0) s = 0;
        if (s < 5) return "now";
        if (s < 60) return (int)s + " s";
        if (s < 3600) return (int)(s / 60) + " min";
        if (s < 86400) return (int)(s / 3600) + " h";
        return (int)(s / 86400) + " d";
    }

    /// <summary>Allow/Block from the compact feed — builds the same rule the CLI would (host rule for that app).</summary>
    public bool CreateRuleFromCompact(CompactRowVm row, bool allow)
    {
        try
        {
            var rule = new Rule
            {
                Action = allow ? RuleAction.Allow : RuleAction.Deny,
                Destination = row.Host,
                Kind = Outbound.Core.Rules.DestKind.Host,
                PortSpec = row.Port.ToString(),
                Protocol = row.Proto.StartsWith("UDP", StringComparison.OrdinalIgnoreCase) ? ProtoSpec.Udp : ProtoSpec.Tcp,
                Source = RuleSources.User,
            };
            if (!string.IsNullOrEmpty(row.ExePath)) rule.AppMatcher = row.ExePath;
            rule.ResolveDestination();
            rule.StampLifetime(DateTime.UtcNow);
            _store.Add(rule);
            RefreshRules();
            UpdateStatus((allow ? " · allowed " : " · blocked ") + row.Host);
            return true;
        }
        catch (Exception ex)
        {
            StatusText.Text = "rule not created: " + ex.Message;
            return false;
        }
    }

    /// <summary>
    /// WPF silently falls back when a FontFamily cannot be resolved, so measure a known string with
    /// the bundled families and with a bogus family: different widths = the bundled font is really used.
    /// </summary>
    private void GetMapOrigin()
    {
        if (_mapOrigin != null) return;
        // Origin = this PC's location from Settings › Location (default Abu Dhabi). SPEC-UI §0.2.
        var c = AppLocation.Load();
        _mapOrigin = (c.Lat, c.Lon);
    }

    // ---------- Appearance (Settings › Appearance) ----------
    private bool _themeLoading;

    private void LoadThemeUi()
    {
        _themeLoading = true;
        try
        {
            string cur = ThemeManager.Current;
            foreach (var item in CmbTheme.Items)
                if (item is ComboBoxItem ci && (ci.Tag as string) == cur) { CmbTheme.SelectedItem = ci; break; }
            TxtThemeHint.Text = "Current: " + ThemeManager.Describe(cur) + " — switches live, no restart. Midnight uses a navy glass palette; the map and globe follow it.";
        }
        catch { }
        finally { _themeLoading = false; }
    }

    private void CmbTheme_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_themeLoading) return;
        if (CmbTheme.SelectedItem is not ComboBoxItem item) return;
        string theme = item.Tag as string ?? "Dark";
        ThemeManager.Apply(theme, this);
        UpdateThemeButtons();
        LoadThemeUi();
        _lastMapPush = 0; // push the new theme to the map page at once
    }

    // ---------- Location (Settings › Location) ----------
    private bool _originLoading;

    private void LoadOriginUi()
    {
        _originLoading = true;
        try
        {
            CmbOriginCity.ItemsSource = CityCatalog.All.Select(c => c.Label).ToList();
            var cur = AppLocation.Load();
            string label = cur.Label;
            if (!CmbOriginCity.Items.Contains(label)) label = CityCatalog.Default.Label;
            CmbOriginCity.SelectedItem = label;
            CmbOriginCity.Text = label;
            TxtOriginHint.Text = "Origin: " + cur.Label + " (" + cur.Lat.ToString("F3") + ", " + cur.Lon.ToString("F3") + ") — the map centres here and draws its arcs from it.";
        }
        catch { /* the picker is cosmetic if the city list is missing */ }
        finally { _originLoading = false; }
    }

    private void CmbOriginCity_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_originLoading) return;
        string label = (CmbOriginCity.SelectedItem as string) ?? CmbOriginCity.Text ?? "";
        OriginCity? city = CityCatalog.All.FirstOrDefault(c => c.Label == label);
        if (city == null) city = CityCatalog.All.FirstOrDefault(c => c.Name == label);
        if (city == null) return; // free text that doesn't match a city — leave as is
        AppLocation.Save(city);
        _mapOrigin = null;   // the next push picks up the new origin
        _lastMapPush = 0;    // and pushes at once, so the map re-centres immediately
        TxtOriginHint.Text = "Origin: " + city.Label + " (" + city.Lat.ToString("F3") + ", " + city.Lon.ToString("F3") + ") — the map centres here and draws its arcs from it.";
    }

    /// <summary>Pushes the current destinations + per-minute totals to the map page (~1×/s while visible).</summary>
    private async void PushMapData(DateTime nowUtc)
    {
        if (_mapWebCore == null || !_mapReady) return;
        long ticks = nowUtc.Ticks;
        if (ticks - _lastMapPush < TimeSpan.FromMilliseconds(900).Ticks) return;

        GetMapOrigin();
        var (olat, olon) = _mapOrigin!.Value;
        long minuteIdx = ticks / TimeSpan.TicksPerMinute;

        var dests = new List<object>();
        foreach (var grp in _groups.Values)
            foreach (var d in grp.AllDests.Values)
                if (!d.IsLocal && d.Lat.HasValue && d.Lon.HasValue)
                    dests.Add(new { app = grp.Name, host = d.Host, city = d.GeoCity, country = d.GeoCountry, cc = d.GeoCc,
                        lat = d.Lat.Value, lon = d.Lon.Value, bytes = d.BytesRaw, blocked = d.DecisionIsDeny,
                        lastSeenMin = (long)(d.LastSeenUtc.Ticks / TimeSpan.TicksPerMinute) });

        var totals = new Dictionary<long, long>();
        foreach (var grp in _groups.Values)
            foreach (var kv in grp.MinuteBuckets)
                if (kv.Key >= minuteIdx - 60) totals[kv.Key] = totals.GetValueOrDefault(kv.Key) + kv.Value;
        var buckets = totals.OrderBy(k => k.Key).Select(k => new long[] { k.Key, k.Value }).ToArray();

        string json = System.Text.Json.JsonSerializer.Serialize(new { origin = new { lat = olat, lon = olon }, theme = ThemeManager.Current, dests, minuteBuckets = buckets });
        try
        {
            // PostWebMessageAsJson is a no-op on this WebView2 build — inject via ExecuteScriptAsync instead.
            string escaped = json.Replace("\\", "\\\\").Replace("'", "\\'");
            string result = await _mapWebCore.ExecuteScriptAsync(
                $"(function(){{ try {{ window.__push('{escaped}'); var s=document.getElementById('stat')?document.getElementById('stat').textContent:'NOSTAT'; var c=document.querySelector('.globe-canvas canvas'); return 'ok:' + s + ' | globe:' + (window.__globe?'yes':'no') + ' canvas:' + (c? c.width+'x'+c.height : 'none'); }} catch(e) {{ return 'ERR:' + e.message; }} }})()");
            _lastMapPush = ticks; MapDebug($"pushed dests={dests.Count} buckets={buckets.Length} page-says: {result}");
            if (!_mapSelfTested && dests.Count >= 3 && buckets.Length >= 2)
            {
                _mapSelfTested = true; // one-shot: verify themes + chart drag-filter on first data-rich push
                try { MapDebug("selftest: " + await _mapWebCore.ExecuteScriptAsync("window.__selftest()")); }
                catch (Exception ex) { MapDebug("selftest-failed: " + ex.Message); }
            }
        }
        catch (Exception ex) { MapDebug("post-failed: " + ex.Message); } // page may be mid-navigation
    }

    private void UpdateGroup(AppGroupVm grp, List<FlowStats> list, DateTime nowUtc)
    {
        long bytes = 0; int allowed = 0, blocked = 0; DateTime lastSeen = DateTime.MinValue;
        FlowStats? primary = null; long primaryBytes = -1;
        foreach (var f in list)
        {
            long b = Interlocked.Read(ref f.BytesSent) + Interlocked.Read(ref f.BytesRecv);
            bytes += b;
            if (f.Decision == "deny") blocked++; else allowed++;
            if (f.LastSeenUtc > lastSeen) lastSeen = f.LastSeenUtc;
            string fk = f.Key.ToString();
            if (!grp.AllDests.TryGetValue(fk, out var d))
            {
                d = new DestRowVm { FlowKey = fk };
                grp.AllDests[fk] = d;
            }
            d.Pid = f.Pid; d.RemoteIp = f.RemoteIp; d.Port = f.RemotePort;
            d.Proto = f.Proto.ToString().ToUpperInvariant();
            d.Host = f.Host ?? f.RemoteIp; d.Domain = f.Domain;
            d.Geo = f.Geo.ToString(); d.BytesRaw = b; d.BytesDisplay = FormatBytes(b);
            d.LastSeenUtc = f.LastSeenUtc; d.LastSeen = WhenText(f.LastSeenUtc);
            d.IsLocal = f.Geo.IsLocal; d.HasCountry = f.Geo.CountryCode != null;
            d.Lat = f.Geo.Lat; d.Lon = f.Geo.Lon; d.GeoCity = f.Geo.City; d.GeoCountry = f.Geo.Country; d.GeoCc = f.Geo.CountryCode;
            d.DecisionIsDeny = f.Decision == "deny";
            if (b > primaryBytes) { primaryBytes = b; primary = f; }
        }
        grp.BytesRaw = bytes;
        // Last-hour sparkline data: delta of session totals between ticks, bucketed per UTC minute.
        long minuteIdx = nowUtc.Ticks / TimeSpan.TicksPerMinute;
        if (grp.PrevTotalBytes == 0)
            grp.PrevTotalBytes = bytes; // first observation — no baseline yet
        else
        {
            long delta = Math.Max(0, bytes - grp.PrevTotalBytes);
            if (delta > 0) grp.MinuteBuckets[minuteIdx] = grp.MinuteBuckets.GetValueOrDefault(minuteIdx) + delta;
            grp.PrevTotalBytes = bytes;
        }
        foreach (var k in grp.MinuteBuckets.Keys.Where(k => k < minuteIdx - 60).ToList())
            grp.MinuteBuckets.Remove(k);
        grp.SparkImage = RenderSparkline(grp, minuteIdx);
        grp.Subline = $"{list.Count} destination{(list.Count == 1 ? "" : "s")} · signed by {grp.SignerKind switch { SignerKind.Microsoft => "Microsoft Windows", SignerKind.Named => list[0].App.Signer.Display, _ => "Unsigned" }}";
        var lim = _policy.Limits.Find(grp.Key); // Phase 5: daily data limit badge
        if (lim != null)
            grp.Subline += $" · limit {FormatBytes(lim.LimitBytes)} ({Math.Round(lim.Percent * 100, 0):F0}% today){(_policy.Limits.IsBlocked(grp.Key) ? " — BLOCKED until midnight" : "")}";
        if (primary != null)
        {
            grp.PrimaryPid = primary.Pid; grp.PrimaryRemoteIp = primary.RemoteIp; grp.PrimaryPort = primary.RemotePort;
            grp.PrimaryHost = primary.Host ?? primary.RemoteIp;
            grp.PrimaryProto = primary.Proto == Protocol.Udp ? ProtoSpec.Udp : ProtoSpec.Tcp;
        }
    }

    // ---------- Activity page: smart filter tokens + time range (SPEC Phase 3) ----------

    /// <summary>Token words recognized inside the search box text.</summary>
    private static readonly Dictionary<string, string[]> TokenWords = new()
    {
        ["ai"] = new[] { "ai" }, ["ads"] = new[] { "ads", "ad", "tracking" }, ["new"] = new[] { "new" },
        ["unsigned"] = new[] { "unsigned" }, ["microsoft"] = new[] { "microsoft", "ms" },
        ["local"] = new[] { "local" }, ["abroad"] = new[] { "abroad" }, ["heavy"] = new[] { "heavy" },
    };

    private void SyncTokensFromText()
    {
        var words = (TxtSearch.Text ?? "").ToLowerInvariant().Split(new[] { ' ', ',', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        TokAi.IsChecked = words.Contains("ai");
        TokAds.IsChecked = words.Contains("ads") || words.Contains("ad") || words.Contains("tracking");
        TokNew.IsChecked = words.Contains("new");
        TokUnsigned.IsChecked = words.Contains("unsigned");
        TokMicrosoft.IsChecked = words.Contains("microsoft") || words.Contains("ms");
        TokLocal.IsChecked = words.Contains("local");
        TokAbroad.IsChecked = words.Contains("abroad");
        TokHeavy.IsChecked = words.Contains("heavy");
    }

    private void SyncTextFromTokens()
    {
        var toks = new List<string>();
        if (TokAi.IsChecked == true) toks.Add("ai");
        if (TokAds.IsChecked == true) toks.Add("ads");
        if (TokNew.IsChecked == true) toks.Add("new");
        if (TokUnsigned.IsChecked == true) toks.Add("unsigned");
        if (TokMicrosoft.IsChecked == true) toks.Add("microsoft");
        if (TokLocal.IsChecked == true) toks.Add("local");
        if (TokAbroad.IsChecked == true) toks.Add("abroad");
        if (TokHeavy.IsChecked == true) toks.Add("heavy");
        TxtSearch.Text = string.Join(' ', toks);
    }

    /// <summary>Free-text part of the search box after removing token words.</summary>
    private string FreeText()
    {
        var words = (TxtSearch.Text ?? "").ToLowerInvariant().Split(new[] { ' ', ',', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries)
            .Where(w => !TokenWords.Values.Any(toks => toks.Contains(w))).ToList();
        return string.Join(' ', words);
    }

    private DateTime? RangeCutoffUtc()
    {
        switch (CmbRange.SelectedIndex)
        {
            case 0: return DateTime.UtcNow.AddMinutes(-5);
            case 1: return DateTime.UtcNow.AddMinutes(-30);
            case 2: return DateTime.UtcNow.AddHours(-1);
            case 3: return DateTime.UtcNow.AddHours(-6);
            default: return null; // all time (default)
        }
    }

    private void ApplyActivityFilter()
    {
        string text = FreeText();
        var cutoff = RangeCutoffUtc();
        if (cutoff == null) RangeNote.Text = "";
        else RangeNote.Text = $"since {cutoff.Value.ToLocalTime().ToString("HH:mm")}";

        bool ai = TokAi.IsChecked == true, ads = TokAds.IsChecked == true, neu = TokNew.IsChecked == true;
        bool unsig = TokUnsigned.IsChecked == true, ms = TokMicrosoft.IsChecked == true;
        bool local = TokLocal.IsChecked == true, abroad = TokAbroad.IsChecked == true, heavy = TokHeavy.IsChecked == true;

        var selectedKey = ActivityList.SelectedItem is AppGroupVm sel ? sel.Key : null;
        Apps.Clear();
        int shown = 0;
        foreach (var grp in _groups.Values.Where(g => PassesAppFilter(g, text, ai, ads, neu, unsig, ms, local, abroad, heavy))
                     .OrderByDescending(g => g.BytesRaw).Take(100))
        {
            // Time range: keep only destinations seen inside the window.
            var visible = grp.AllDests.Values.Where(d => cutoff == null || d.LastSeenUtc >= cutoff.Value)
                .OrderByDescending(d => d.BytesRaw).ToList();
            if (visible.Count == 0) continue;
            grp.Dests.Clear();
            foreach (var d in visible) grp.Dests.Add(d);
            long vb = visible.Sum(d => d.BytesRaw);
            grp.BytesDisplay = FormatBytes(vb);
            grp.Counts = $"{grp.AllDests.Values.Count(d => d.DecisionIsDeny)} blocked · {visible.Count} shown";
            grp.LastSeen = WhenText(visible.Max(d => d.LastSeenUtc));
            Apps.Add(grp);
            shown++;
        }
        if (selectedKey != null && Apps.Any(a => a.Key == selectedKey))
            ActivityList.SelectedItem = Apps.First(a => a.Key == selectedKey);
    }

    private bool PassesAppFilter(AppGroupVm g, string text, bool ai, bool ads, bool neu, bool unsig, bool ms, bool local, bool abroad, bool heavy)
    {
        if (text.Length > 0)
        {
            bool hit = g.Name.ToLowerInvariant().Contains(text) ||
                       (g.ExePath != null && Path.GetFileName(g.ExePath).ToLowerInvariant().Contains(text)) ||
                       g.AllDests.Values.Any(d => d.Host.ToLowerInvariant().Contains(text) ||
                                                   (d.Domain != null && d.Domain.ToLowerInvariant().Contains(text)) ||
                                                   d.RemoteIp.Contains(text));
            if (!hit) return false;
        }
        var dests = g.AllDests.Values.ToList();
        if (ai)
        {
            bool hit = g.Name.ToLowerInvariant() is string n && AiApps.Any(t => n.Contains(t)) ||
                       dests.Any(d => AiApps.Any(t => d.Host.ToLowerInvariant().Contains(t)));
            if (!hit) return false;
        }
        if (ads && !dests.Any(d => AdHosts.Any(t => d.Host.ToLowerInvariant().Contains(t)))) return false;
        if (neu)
        {
            _appFirstSeen.TryGetValue(g.Key, out var first);
            if (DateTime.UtcNow - first > TimeSpan.FromHours(1)) return false; // "new" = first connection seen within the last hour
        }
        if (unsig && g.SignerKind != SignerKind.Unsigned) return false;
        if (ms)
        {
            bool hit = g.SignerKind == SignerKind.Microsoft ||
                       (g.ExePath != null && MsServices.Any(t => g.ExePath.ToLowerInvariant().Contains(t))) ||
                       (g.Name is string nm && MsServices.Any(t => nm.ToLowerInvariant().Contains(t)));
            if (!hit) return false;
        }
        if (local && !dests.All(d => d.IsLocal)) return false;
        if (abroad && !dests.Any(d => !d.IsLocal && d.HasCountry)) return false;
        if (heavy && g.BytesRaw < 10_000_000) return false; // heavy = ≥ 10 MB this session
        return true;
    }

    /// <summary>Draws the app's last-hour per-minute byte sparkline (ScottPlot → WPF ImageSource).</summary>
    private static ImageSource? RenderSparkline(AppGroupVm grp, long minuteIdx)
    {
        try
        {
            var plt = grp.SparkPlot ?? new Plot();
            grp.SparkPlot = plt;
            plt.Clear();
            // Transparent background so the sparkline blends into light/dark themes.
            plt.FigureBackground.Color = ScottPlot.Color.FromHex("#00000000");
            plt.DataBackground.Color = ScottPlot.Color.FromHex("#00000000");
            double[] vals = new double[61];
            for (int i = 0; i <= 60; i++)
                vals[i] = grp.MinuteBuckets.GetValueOrDefault(minuteIdx - 60 + i);
            var sig = plt.Add.Signal(vals);
            sig.LineWidth = 1.5f;
            sig.Color = ScottPlot.Color.FromHex("#2563EB");
            double maxV = vals.Max();
            plt.Axes.SetLimitsY(0, Math.Max(1, maxV * 1.15));
            plt.HideAxesAndGrid();
            var img = plt.GetImage(138, 40);
            byte[] png = ((ScottPlot.Image)img).GetImageBytes(); // PNG by default — WPF decodes it natively
            using var ms = new System.IO.MemoryStream(png, writable: false);
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.StreamSource = ms;
            bi.EndInit();
            bi.Freeze();
            return bi;
        }
        catch { return null; } // sparkline is cosmetic — never break the render loop
    }

    private static ImageSource? LoadAppIcon(string? exePath)
    {
        if (string.IsNullOrEmpty(exePath)) return null;
        try
        {
            var icon = System.Drawing.Icon.ExtractAssociatedIcon(exePath);
            if (icon == null) return null;
            using var ms = new MemoryStream();
            icon.Save(ms);
            ms.Position = 0;
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.StreamSource = ms;
            bmp.EndInit();
            return bmp;
        }
        catch { return null; }
    }

    private void RenderOverview()
    {
        var s = _policy.Engine.Settings;
        OvMode.Text = ModeNames.Of(s.Mode);
        OvEnforce.Text = "enforcement dry-run — no firewall changes";
        OvSource.Text = _engine.Source;
        OvEvents.Text = $"{_engine.NetEvents} net · {_engine.DnsEvents} dns events";

        var flows = _engine.Snapshot();
        OvAppsOnline.Text = flows.Select(f => f.App.Key).Distinct().Count().ToString();
        OvFlows.Text = $"{flows.Count} live connections";

        var c = _policy.Counts();
        OvAllowed.Text = c.Allowed.ToString();
        OvBlocked.Text = c.Blocked.ToString();

        var topApps = flows
            .GroupBy(f => f.App.DisplayName)
            .Select(g => new TopAppVm(g.Key, FormatBytes(g.Sum(x => x.BytesRecv + x.BytesSent)), g.Sum(x => x.BytesRecv + x.BytesSent)))
            .OrderByDescending(t => t.BytesRaw).Take(5).ToList();
        OvTopApps.ItemsSource = topApps;
        var blocked = _policy.ReviewItems().Where(i => i.Action == ReviewAction.Blocked).Take(8);
        OvBlockedHosts.ItemsSource = blocked.Select(i => new BlockedHostVm(i.Host ?? i.RemoteIp, WhenText(i.SeenUtc))).ToList();
    }

    /// <summary>Inspector: explain why this connection was allowed/blocked (deciding rule).</summary>
    private void UpdateInspector()
    {
        if (ActivityList.SelectedItem is not AppGroupVm vm) return;
        var ctx = new FlowContext(vm.PrimaryPid, vm.Name, "", vm.PrimaryRemoteIp, vm.PrimaryPort, vm.PrimaryHost, vm.PrimaryProto);
        var (rule, reason) = RuleMatcher.Decide(_policy.Engine.Rules, ctx, DateTime.UtcNow, SystemKeys.Current());
        InspTitle.Text = $"{vm.Name} → {vm.PrimaryHost}:{vm.PrimaryPort}";
        string why;
        if (rule != null)
            why = $"Decided by rule #{rule.Id}: {rule.Describe()}";
        else
            switch (_policy.Engine.Settings.Mode)
            {
                case Mode.Ask: why = "No matching rule — Ask mode prompts you on the first connection."; break;
                case Mode.Strict: why = "No matching rule — Strict mode blocks it (recorded in Review)."; break;
                default: why = "No matching rule — Learn mode allows it and records it in Review."; break;
            }
        InspBody.Text = $"{why}\n\n{reason} · {vm.Subline}";
    }

    private static string WhenText(DateTime utc) => utc.ToLocalTime().ToString("HH:mm:ss");

    // ---------- Rules page ----------

    private void RefreshRules()
    {
        Rules.Clear();
        foreach (var r in _store.All()) Rules.Add(new RuleRowVm(r));
        RulesHint.Text = $"{Rules.Count} rules";
    }

    private void AddRuleFromForm()
    {
        string dest = TxtDest.Text.Trim();
        if (dest.Length == 0) { MessageBox.Show(this, "Destination is required.", "OutGate"); return; }
        string action = ((ComboBoxItem)CmbAction.SelectedItem)?.Content.ToString() ?? "Deny";
        var rule = new Rule
        {
            Action = action == "Allow" ? RuleAction.Allow : RuleAction.Deny,
            AppMatcher = string.IsNullOrWhiteSpace(TxtApp.Text) ? null : TxtApp.Text.Trim(),
            Destination = dest,
            PortSpec = string.IsNullOrWhiteSpace(TxtPort.Text) || TxtPort.Text.Trim() == "any" ? "any" : TxtPort.Text.Trim(),
        };
        switch (((ComboBoxItem)CmbLifetime.SelectedItem)?.Content.ToString())
        {
            case "1 hour": rule.Lifetime = LifetimeKind.Hours; break;
            case "Until app quits": rule.Lifetime = LifetimeKind.UntilQuit; break;
            case "Once (next match)": rule.Lifetime = LifetimeKind.Once; break;
            default: rule.Lifetime = LifetimeKind.Forever; break;
        }
        rule.StampLifetime(DateTime.UtcNow);
        rule.ResolveDestination();
        _store.Add(rule);
        _policy.ReloadRules(); // engine must see the new rule immediately (Ask-mode prompts depend on it)
        RefreshRules();
    }

    private void DeleteSelectedRule()
    {
        if (RulesGrid.SelectedItem is not RuleRowVm vm) return;
        _store.Remove(vm.Id);
        _policy.ReloadRules();
        RefreshRules();
    }

    // ---------- Review page ----------

    private void RefreshReview()
    {
        var items = _policy.ReviewItems().Take(200).ToList();
        Review.Clear();
        foreach (var i in items)
            Review.Add(new ReviewRowVm { Id = i.Id, AppName = i.AppName, HostOrIp = i.Host ?? i.RemoteIp, PortProto = $"{i.Port} · {i.Proto}", Reason = i.Reason, WhenDisplay = WhenText(i.SeenUtc), ActionText = ReviewActionNames.Of(i.Action) });
    }

    private void ReviewAllow_Click(object sender, RoutedEventArgs e) => AnswerReview(sender, RuleAction.Allow);
    private void ReviewBlock_Click(object sender, RoutedEventArgs e) => AnswerReview(sender, RuleAction.Deny);

    private void AnswerReview(object sender, RuleAction action)
    {
        if (((System.Windows.Controls.Control)sender).Tag is not long id) return;
        _policy.Answer(id, action, LifetimeKind.Forever, "port", null); // becomes a rule (SPEC: allow/block per item → rule)
        RefreshReview();
    }

    private void ReviewDismiss_Click(object sender, RoutedEventArgs e)
    {
        if (((System.Windows.Controls.Control)sender).Tag is not long id) return;
        _policy.SetReviewAction(id, ReviewAction.Dismissed); // just hides it — no rule
        RefreshReview();
    }

    /// <summary>Bulk: trust every app in the list whose binary carries a named or Microsoft signature.</summary>
    private void BtnAllowVerified_Click(object sender, RoutedEventArgs e)
    {
        int trusted = 0;
        foreach (var i in _policy.ReviewItems().Where(i => i.Action is ReviewAction.Pending or ReviewAction.Learned).ToList())
        {
            var app = AppResolver.ResolveByExe(i.AppKey.StartsWith("exe:", StringComparison.OrdinalIgnoreCase) ? i.AppKey[4..] : "");
            if (app.Signer.Kind is SignerKind.Named or SignerKind.Microsoft)
            {
                string? exe = app.ExePath;
                _policy.TrustApp(i.AppKey, app, exe == null ? null : AppTrustStore.Sha256Of(exe));
                trusted++;
            }
        }
        MessageBox.Show(this, $"Trusted {trusted} verified publisher(s). Their allow rules are no longer suspended on binary change.", "OutGate");
    }

    // ---------- Enforcement (dry-run held) ----------

    private void ApplyRules()
    {
        bool dry = ChkDryRun.IsChecked == true;
        var plan = EnforcementPlanner.Plan(_store.All(), new FirewallEnforcer().EnumerateInstalledRuleNames());
        string body = "Dry-run: " + (dry ? "yes" : "no");
        body += " | to-add: " + plan.AddCommands.Count + " | to-remove: " + plan.RemoveCommands.Count;
        MessageBox.Show(this, body, "OutGate — enforcement");
    }

    private void ClearFirewallRules()
    {
        bool dry = ChkDryRun.IsChecked == true;
        using var enforcer = new FirewallEnforcer(dry);
        var res = enforcer.Clear();
        string body = $"Dry-run: {(dry ? "yes" : "no")}";
        body += $" | rules removed: {res.CommandsRun.Count}";
        if (res.Error != null) body += $" | {res.Error}";
        MessageBox.Show(this, body, "OutGate — enforcement");
    }

    private void UpdateStatus(string note = "")
    {
        string elev = FirewallEnforcer.CheckElevation() ? "elevated" : "user-mode";
        string mon = _engine.LiveMonitoring
            ? $"{_engine.Source} · {_engine.NetEvents} net / {_engine.DnsEvents} dns events"
            : $"monitoring OFF ({_engine.Source})";
        StatusText.Text = $"{mon} · {elev}{note}";
        UpdateMonitoringBanner();
    }

    /// <summary>Overview banner: when live monitoring is off, say so instead of showing zeros.</summary>
    private void UpdateMonitoringBanner()
    {
        try
        {
            if (_engine.LiveMonitoring)
            {
                OvMonitoringBanner.Visibility = Visibility.Collapsed;
                return;
            }
            string reason = string.IsNullOrEmpty(_engine.MonitoringReason) ? "live monitoring is not running" : _engine.MonitoringReason;
            OvMonitoringTitle.Text = "Live monitoring is off: " + (reason.Length > 120 ? reason[..120] + "…" : reason);
            OvMonitoringDetail.Text = "Byte counts, per-app traffic and per-connection detail come from the kernel ETW session. "
                + "Close OutGate and start it again as administrator (right-click → Run as administrator, or the desktop shortcut) — "
                + "details were written to %LocalAppData%\\OutboundWin\\engine.log.";
            OvMonitoringBanner.Visibility = Visibility.Visible;
        }
        catch { /* the banner must never break rendering */ }
    }

    // ---------- Settings page ----------

    private void LoadSettingsUi()
    {
        var s = _policy.Engine.Settings;
        CmbMode.SelectedIndex = s.Mode switch { Mode.Learn => 0, Mode.Ask => 1, _ => 2 };
        TxtTcpTimeout.Text = s.Timeouts.TcpSeconds.ToString();
        TxtUdpTimeout.Text = s.Timeouts.UdpSeconds.ToString();
        ChkBlockUnanswered.IsChecked = s.BlockWhenPromptUnanswered;
        ChkBlockNewApps.IsChecked = s.BlockNewAppsUntilAnswered;
        LoadOriginUi();
        LoadThemeUi();
    }

    private void BtnApplySettings_Click(object sender, RoutedEventArgs e)
    {
        var s = _policy.Engine.Settings;
        string modeText = ((ComboBoxItem)CmbMode.SelectedItem)?.Content.ToString() switch
        { "Learn (allow + review)" => "Learn", "Ask (prompt on new connections)" => "Ask", _ => "Strict" };
        if (Enum.TryParse<Mode>(modeText, true, out var m)) s.Mode = m;
        if (int.TryParse(TxtTcpTimeout.Text.Trim(), out int tcp) && tcp is >= 15 and <= 120)
            s.Timeouts.TcpSeconds = tcp;
        if (int.TryParse(TxtUdpTimeout.Text.Trim(), out int udp) && udp is >= 2 and <= 120)
            s.Timeouts.UdpSeconds = udp;
        s.BlockWhenPromptUnanswered = ChkBlockUnanswered.IsChecked == true;
        s.BlockNewAppsUntilAnswered = ChkBlockNewApps.IsChecked == true;

        // Persist (theme + policy settings + location share %LOCALAPPDATA%\OutboundWin\settings.json).
        try
        {
            string theme = ApplicationThemeManager.GetAppTheme() == ApplicationTheme.Dark ? "Dark" : "Light";
            var mode = s.Mode; var tcp2 = s.Timeouts.TcpSeconds; var udp2 = s.Timeouts.UdpSeconds;
            bool bu = s.BlockWhenPromptUnanswered, bn = s.BlockNewAppsUntilAnswered;
            AppSettingsFile.Update(o =>
            {
                o["theme"] = theme;
                o["mode"] = ModeNames.Of(mode);
                o["tcpTimeout"] = tcp2;
                o["udpTimeout"] = udp2;
                o["blockUnanswered"] = bu;
                o["blockNewApps"] = bn;
            });
        }
        catch { /* settings persistence is best-effort */ }

        UpdateStatus();
    }

    // ---------- Profiles (per network) ----------

    private bool _profilesLoading; // true while the profile combo is rebuilt (its SelectionChanged must not write back)

    private void LoadProfilesUi()
    {
        var p = _policy.Profiles;
        _profilesLoading = true; // Items.Clear/SelectedIndex below fire SelectionChanged — don't treat that as a user choice
        try
        {
        TxtCurrentNetwork.Text = "current network: " + (string.IsNullOrEmpty(p.CurrentNetwork) ? "— (offline?)" : p.CurrentNetwork);
        LstProfiles.Items.Clear();
        foreach (var prof in p.Profiles)
        {
            var row = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
            string mapped = p.NetworkMap.FirstOrDefault(kv => kv.Value == prof.Name).Key;
            row.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = $"{prof.Name} — {ModeNames.Of(prof.Mode)}" + (mapped != null ? $"  [auto: {mapped}]" : "") + (p.ActiveProfile == prof.Name ? "   ● active" : ""),
                Foreground = (Brush)FindResource("TextFillColorPrimaryBrush"),
            });
            var del = new Wpf.Ui.Controls.Button { Content = "delete", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(10, 0, 0, 0) };
            del.Click += (_, _) => { p.Profiles.Remove(prof); if (p.ActiveProfile == prof.Name) p.SetActive(null); RefreshProfilesUi(); };
            row.Children.Add(del);
            LstProfiles.Items.Add(row);
        }
        CmbActiveProfile.Items.Clear();
        CmbActiveProfile.Items.Add("(none — global mode applies)");
        foreach (var prof in p.Profiles) CmbActiveProfile.Items.Add(prof.Name);
        int idx = p.ActiveProfile == null ? 0 : p.Profiles.FindIndex(x => x.Name == p.ActiveProfile) + 1;
        if (idx >= 0 && idx < CmbActiveProfile.Items.Count) CmbActiveProfile.SelectedIndex = idx;
        }
        finally { _profilesLoading = false; }
    }

    private void RefreshProfilesUi() { Dispatcher.BeginInvoke(LoadProfilesUi); }

    private void BtnAddProfile_Click(object sender, RoutedEventArgs e)
    {
        string name = TxtProfileName.Text.Trim();
        if (name.Length == 0 || _policy.Profiles.Profiles.Any(x => x.Name == name)) return;
        var modeText = ((ComboBoxItem)CmbProfileMode.SelectedItem)?.Content.ToString() switch
        { "Ask (prompt on new connections)" => Mode.Ask, "Strict (deny until allowed)" => Mode.Strict, _ => Mode.Learn };
        _policy.Profiles.Profiles.Add(new Profile { Name = name, Mode = modeText });
        TxtProfileName.Clear();
        RefreshProfilesUi();
    }

    private void CmbActiveProfile_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Rebuilding the list (Items.Clear) fires this with SelectedIndex == -1; guard before
        // indexing, otherwise "idx - 1 < Count" is true for -2 and the app crashes on startup.
        // Also ignore changes made by LoadProfilesUi itself, otherwise SetActive → Changed →
        // RefreshProfilesUi → LoadProfilesUi loops forever and the Settings page hangs.
        if (_profilesLoading) return;
        int idx = CmbActiveProfile.SelectedIndex;
        if (idx < 0) return;
        var profiles = _policy.Profiles.Profiles;
        if (idx == 0) { _policy.Profiles.SetActive(null); return; }
        if (idx - 1 < profiles.Count) _policy.Profiles.SetActive(profiles[idx - 1].Name);
    }

    private void BtnMapNetwork_Click(object sender, RoutedEventArgs e)
    {
        var p = _policy.Profiles;
        if (string.IsNullOrEmpty(p.CurrentNetwork)) return; // offline — nothing to map
        int idx = CmbActiveProfile.SelectedIndex;
        string? profile = (idx <= 0 || idx - 1 >= p.Profiles.Count) ? null : p.Profiles[idx - 1].Name;
        if (profile != null) p.MapNetwork(p.CurrentNetwork, profile);
    }

    // ---------- Blocklists (over HTTPS) ----------

    private void LoadBlocklistsUi()
    {
        var b = _policy.Blocklists;
        TxtBlocklistTotal.Text = "loaded entries: " + b.TotalEntries.ToString("N0");
        LstBlocklists.Items.Clear();
        foreach (var sub in b.Subs)
        {
            var row = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
            string status = sub.LastError != null ? $"  ⚠ last fetch failed ({sub.LastError}) — using cached list" : (sub.LastOkUtc != null ? $"  ✓ fetched {sub.LastOkUtc:u}" : "  not fetched yet");
            row.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = $"{(sub.Enabled ? "" : "[off] ")}{sub.Name} — {sub.EntryCount:N0} entries ({sub.Url}){status}",
                Foreground = (Brush)FindResource("TextFillColorPrimaryBrush"),
                TextWrapping = TextWrapping.Wrap,
            });
            var toggle = new Wpf.Ui.Controls.Button { Content = sub.Enabled ? "disable" : "enable", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(10, 0, 0, 0) };
            toggle.Click += (_, _) => { b.SetEnabled(sub.Name, !sub.Enabled); RefreshBlocklistsUi(); };
            row.Children.Add(toggle);
            var del = new Wpf.Ui.Controls.Button { Content = "delete", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(6, 0, 0, 0) };
            del.Click += (_, _) => { b.RemoveSub(sub.Name); RefreshBlocklistsUi(); };
            row.Children.Add(del);
            LstBlocklists.Items.Add(row);
        }
    }

    private void RefreshBlocklistsUi() { Dispatcher.BeginInvoke(LoadBlocklistsUi); }

    private void BtnAddBlocklist_Click(object sender, RoutedEventArgs e)
    {
        string name = TxtBlocklistName.Text.Trim();
        string url = TxtBlocklistUrl.Text.Trim();
        if (name.Length == 0 || !Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http")) return;
        try { _policy.Blocklists.AddSub(name, url); } catch { return; } // duplicate name — leave inputs for correction
        TxtBlocklistName.Clear();
        TxtBlocklistUrl.Clear();
    }

    private void BtnRefreshBlocklists_Click(object sender, RoutedEventArgs e) =>
        Task.Run(async () => await _policy.Blocklists.RefreshAsync());

    // ---------- Data limits (per app, daily) ----------

    /// <summary>Resolve an app name/path against the apps the engine has seen (bare names match the exe file name).</summary>
    private string NormalizeAppKey(string app) =>
        Outbound.Core.Identity.AppResolver.NormalizeAppKey(app, _engine.Snapshot().Select(f => f.App.ExePath).Where(p => !string.IsNullOrEmpty(p)));

    private void LoadLimitsUi()
    {
        var l = _policy.Limits;
        TxtLimitTotal.Text = $"{l.All().Count} limit(s)";
        LstLimits.Items.Clear();
        foreach (var lim in l.All())
        {
            var row = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
            string name = IpcServer.LimitName(lim.AppKey);
            string status = l.IsBlocked(lim.AppKey) ? " — BLOCKED until midnight" : "";
            row.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = $"{name} — {FormatBytes(lim.LimitBytes)}/day · used {FormatBytes(lim.TodayBytes)} ({Math.Round(lim.Percent * 100, 0):F0}% today){status}",
                Foreground = (Brush)FindResource("TextFillColorPrimaryBrush"),
            });
            var del = new Wpf.Ui.Controls.Button { Content = "remove", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(10, 0, 0, 0) };
            del.Click += (_, _) => { l.Clear(lim.AppKey); RefreshLimitsUi(); };
            row.Children.Add(del);
            LstLimits.Items.Add(row);
        }
    }

    private void RefreshLimitsUi() { Dispatcher.BeginInvoke(LoadLimitsUi); }

    private void BtnAddLimit_Click(object sender, RoutedEventArgs e)
    {
        string app = TxtLimitApp.Text.Trim();
        if (app.Length == 0) return;
        try
        {
            long bytes = IpcServer.ParseBytes(TxtLimitBytes.Text.Trim());
            _policy.Limits.Set(NormalizeAppKey(app), bytes, false); // persists + fires Changed → re-render
            TxtLimitApp.Clear();
            TxtLimitBytes.Clear();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "OutGate — data limit"); }
    }

    // ---------- Theme ----------

    private void ToggleTheme()
    {
        // Quick switch: Dark → Light → Midnight → Dark. The full four-way picker lives in Settings › Appearance.
        string next = ThemeManager.Current switch
        {
            "Dark" => "Light",
            "Light" => "Midnight",
            "Midnight" => "Dark",
            _ => "Dark",
        };
        ThemeManager.Apply(next, this);
        UpdateThemeButtons();
    }

    private void UpdateThemeButtons()
    {
        string label = ThemeManager.Current switch
        {
            "Dark" => "Light theme",
            "Light" => "Midnight theme",
            "Midnight" => "Dark theme",
            _ => "Dark theme",
        };
        BtnThemeToggle.Content = label;
        BtnThemeToggle2.Content = label;
    }

    private static string FormatBytes(long b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024L * 1024) return $"{b / 1024.0:F1} KB";
        if (b < 1024L * 1024 * 1024) return $"{b / (1024.0 * 1024):F1} MB";
        return $"{b / (1024.0 * 1024 * 1024):F2} GB";
    }
}

/// <summary>One app row on the Activity page: icon, name, N destinations, signer, sparkline, counts, last seen.</summary>
public sealed class AppGroupVm
{
    public string Key { get; init; } = "";
    public string Name { get; set; } = "";
    public string? ExePath { get; set; }
    public SignerKind SignerKind { get; set; }
    public ImageSource? Icon { get; set; }
    public string Subline { get; set; } = "";
    public long BytesRaw { get; set; }
    public string BytesDisplay { get; set; } = "0 B";
    public string Counts { get; set; } = "";
    public string LastSeen { get; set; } = "";

    // Inspector context: the app's biggest destination.
    public int PrimaryPid { get; set; }
    public string PrimaryRemoteIp { get; set; } = "";
    public ushort PrimaryPort { get; set; }
    public string? PrimaryHost { get; set; }
    public ProtoSpec PrimaryProto { get; set; }

    // All destinations ever seen (time-range filter works on this); Dests = the visible subset.
    public Dictionary<string, DestRowVm> AllDests { get; } = new();
    public ObservableCollection<DestRowVm> Dests { get; } = [];

    // Last-hour sparkline: rendered per tick into SparkImage (ScottPlot Plot → SkiaSharp bitmap).
    public ImageSource? SparkImage { get; set; }
    internal ScottPlot.Plot? SparkPlot { get; set; }
    /// <summary>Bytes per minute for the last hour, keyed by absolute UTC minute index.</summary>
    public Dictionary<long, long> MinuteBuckets { get; } = new();
    public long PrevTotalBytes { get; set; }
}

/// <summary>One destination row under an app (host with bold registrable domain, port·proto, geo, bytes, last seen).</summary>
public sealed class DestRowVm
{
    public string FlowKey { get; init; } = "";
    public int Pid { get; set; }
    public string RemoteIp { get; set; } = "";
    public ushort Port { get; set; }
    public string Proto { get; set; } = "";
    public string Host { get; set; } = "";
    public string? Domain { get; set; }
    public string Geo { get; set; } = "";
    public long BytesRaw { get; set; }
    public string BytesDisplay { get; set; } = "0 B";
    public DateTime LastSeenUtc { get; set; }
    public string LastSeen { get; set; } = "";
    public bool DecisionIsDeny { get; set; }

    // Local vs abroad, from the geo of this destination.
    public bool IsLocal { get; set; }
    public bool HasCountry { get; set; }

    // Geo coordinates for the Phase 4 map/globe (null = local or unknown).
    public double? Lat { get; set; }
    public double? Lon { get; set; }
    public string? GeoCity { get; set; }
    public string? GeoCountry { get; set; }
    public string? GeoCc { get; set; }

    // Host rendered as: prefix (subdomain part) + bold registrable domain + rest.
    public string HostPrefix => Domain == null ? "" : Host.Length > Domain.Length && Host.EndsWith(Domain, StringComparison.OrdinalIgnoreCase)
        ? Host[..^Domain.Length] : "";
    public string HostDomain => Domain ?? Host;
    public string Rest => $"{Port} {Proto}";
}

public sealed class ReviewRowVm
{
    public long Id { get; init; }
    public string AppName { get; init; } = "";
    public string HostOrIp { get; init; } = "";
    public string PortProto { get; init; } = "";
    public string Reason { get; init; } = "";
    public string WhenDisplay { get; init; } = "";
    public string ActionText { get; init; } = "";
}

public sealed class RuleRowVm
{
    private readonly Rule _r;
    public RuleRowVm(Rule r) => _r = r;
    public long Id => _r.Id;
    public string ActionDisplay => _r.Action.ToString();
    public string AppMatcherDisplay => string.IsNullOrEmpty(_r.AppMatcher) ? "(any app)" : Path.GetFileName(_r.AppMatcher);
    public string Destination => _r.Destination;
    public string PortSpec => _r.PortSpec;
    public string LifetimeDisplay => Rule.LifetimeText(_r.Lifetime);
    public string Priority => _r.IsPriority ? "priority" : "normal";
    public string Source => _r.Source;
    public string ProfileDisplay => _r.Profile ?? "(all)";
}

public sealed record TopAppVm(string Name, string Bytes, long BytesRaw)
{
    /// <summary>Binding-friendly raw bytes (kept for ordering).</summary>
}

public sealed record BlockedHostVm(string Host, string When);

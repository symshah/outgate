using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using H.NotifyIcon;
using Outbound.Core.Engine;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace Outbound.App;

public partial class App : Application
{
    /// <summary>Tray icon (H.NotifyIcon). Created in OnStartup, disposed in OnExit.</summary>
    public TaskbarIcon? Tray { get; private set; }
    /// <summary>The flyout panel inside the tray popup — MainWindow drives its content.</summary>
    public TrayFlyout? Flyout { get; private set; }
    /// <summary>The Ask prompt window (Phase 3 item 3) — created on demand by MainWindow when prompts arrive.</summary>
    public AskWindow? Ask { get; set; }
    /// <summary>Startup mode override from the command line (--mode ask|learn|strict).</summary>
    public static string? StartupMode;
    /// <summary>Startup page override from the command line (--page overview|activity|rules|review|map|settings).</summary>
    public static string? StartupPage;
    private Mutex? _singleInstance;   // one instance only: two would fight over the ETW sessions

    public App()
    {
        // SPEC-GLASS 0.3: global crash handler — log to %LocalAppData%\OutboundWin\crash.log
        // and surface a message box instead of an unexplained vanish.
        this.DispatcherUnhandledException += (s, e) =>
        {
            WriteCrashLog(e.Exception);
            System.Windows.MessageBox.Show("OutGate hit an unexpected error.\n\n" + e.Exception.Message +
                "\n\nDetails were saved to:\n" + CrashLogPath,
                "OutGate", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            e.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (s, e) => WriteCrashLog(e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (s, e) =>
        {
            WriteCrashLog(e.Exception);
            e.SetObserved();
        };
    }

    public static string CrashLogPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "OutboundWin", "crash.log");

    private static void WriteCrashLog(Exception? ex)
    {
        if (ex is null) return;
        try
        {
            var dir = Path.GetDirectoryName(CrashLogPath);
            if (dir is not null) Directory.CreateDirectory(dir);
            File.AppendAllText(CrashLogPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}\n\n");
        }
        catch { /* last-resort logging must never throw */ }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Single instance: a second launch hands over to the running one (bringing its window
        // forward) and exits. Two instances would fight over the same ETW session names, which
        // silently kills byte accounting in both.
        _singleInstance = new Mutex(true, @"Local\OutboundWin.SingleInstance", out bool isFirst);
        if (!isFirst)
        {
            try
            {
                using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", "OutboundWin",
                    System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.CurrentUserOnly);
                pipe.Connect(1500);
                var req = System.Text.Encoding.UTF8.GetBytes("{\"id\":1,\"cmd\":\"ui.activate\"}\n");
                pipe.Write(req, 0, req.Length);
                pipe.Flush();
                EngineLog.Write("second instance: asked the running instance to come forward, exiting");
            }
            catch { /* the running instance is still there; leave quietly */ }

            // Hard exit, NOT Shutdown(): StartupUri still builds MainWindow after OnStartup returns,
            // and that constructor starts the engine — whose StopStaleSessions() would stop the
            // RUNNING instance's ETW sessions and silently kill its byte accounting.
            Environment.Exit(0);
            return;
        }

        // --mode ask|learn|strict (used by tests and quick switching until Settings lands).
        for (int i = 0; i + 1 < e.Args.Length; i++)
        {
            if (string.Equals(e.Args[i], "--mode", StringComparison.OrdinalIgnoreCase))
                StartupMode = e.Args[i + 1].ToLowerInvariant();
            else if (string.Equals(e.Args[i], "--page", StringComparison.OrdinalIgnoreCase))
                StartupPage = e.Args[i + 1].ToLowerInvariant();
        }

        // Apply the persisted theme (System | Light | Dark | Midnight). The window itself is
        // re-skinned in ApplyWindowChrome once MainWindow exists.
        ThemeManager.ApplyInitial();

        // In System mode the app palette follows Windows as it flips light/dark.
        ApplicationThemeManager.Changed += (_, _) =>
        {
            if (ThemeManager.Current == "System")
                ThemeManager.MergePaletteFor(ApplicationThemeManager.GetAppTheme() == ApplicationTheme.Dark);
        };

        // Tray icon + flyout panel (Phase 3 item 2). No assets/ yet → generated text glyph.
        Flyout = new TrayFlyout();
        Tray = new TaskbarIcon
        {
            Icon = new GeneratedIconSource { Text = "O", FontSize = 14, CornerRadius = new System.Windows.CornerRadius(5) }.ToIcon(),
            ToolTipText = "OutGate — outbound firewall monitor",
            TrayPopup = Flyout,   // UIElement: the flyout panel itself
        };
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { ThemeSettings.Save(ThemeManager.Current); } catch { }
        try { _singleInstance?.ReleaseMutex(); _singleInstance?.Dispose(); } catch { }
        try { Tray?.Dispose(); } catch { }
        base.OnExit(e);
    }

    /// <summary>Get-or-create the Ask prompt window (UI thread only). A closed window is replaced on next call.</summary>
    public AskWindow EnsureAsk(Outbound.Core.Policy.PolicyService policy)
    {
        if (Ask != null) return Ask; // already shown — Refresh() updates its content in place
        var w = new AskWindow(policy);
        w.Closed += (_, _) => { if (ReferenceEquals(Ask, w)) Ask = null; };
        Ask = w;
        if (!w.IsVisible) w.Show(); // ShowActivated=False in XAML — never steals focus from the app being typed in
        return w;
    }
}

/// <summary>A city for the map origin picker (bundled Natural Earth populated-places list).</summary>
public sealed record OriginCity(string Name, string Country, double Lat, double Lon)
{
    public string Label => Name + " — " + Country;
}

/// <summary>Reads assets/cities.json (243 major cities, Natural Earth, public domain).</summary>
public static class CityCatalog
{
    private static List<OriginCity>? _all;

    public static IReadOnlyList<OriginCity> All => _all ??= Load();

    private static List<OriginCity> Load()
    {
        var list = new List<OriginCity>();
        try
        {
            string p = System.IO.Path.Combine(AppContext.BaseDirectory, "assets", "cities.json");
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(p));
            foreach (var e in doc.RootElement.EnumerateArray())
            {
                string name = e.GetProperty("name").GetString() ?? "";
                if (name.Length == 0) continue;
                list.Add(new OriginCity(name, e.GetProperty("country").GetString() ?? "",
                    e.GetProperty("lat").GetDouble(), e.GetProperty("lon").GetDouble()));
            }
        }
        catch { /* fall through to the built-in default */ }
        if (list.Count == 0) list.Add(new OriginCity("Abu Dhabi", "United Arab Emirates", 24.4539, 54.3773));
        return list;
    }

    public static OriginCity Default
    {
        get
        {
            foreach (var c in All)
                if (c.Name == "Abu Dhabi") return c;
            return All[0];
        }
    }
}

/// <summary>
/// settings.json as a shared key-value document. Theme, policy settings and the map location all
/// live here, and every writer used to rewrite the whole file — merging instead of clobbering.
/// </summary>
public static class AppSettingsFile
{
    public static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "settings.json");

    public static System.Text.Json.Nodes.JsonObject Read()
    {
        try
        {
            if (File.Exists(Path))
                return System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(Path)) as System.Text.Json.Nodes.JsonObject
                       ?? new System.Text.Json.Nodes.JsonObject();
        }
        catch { }
        return new System.Text.Json.Nodes.JsonObject();
    }

    public static void Update(Action<System.Text.Json.Nodes.JsonObject> mutate)
    {
        try
        {
            var o = Read();
            mutate(o);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            File.WriteAllText(Path, o.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* settings persistence is best-effort */ }
    }
}

/// <summary>The PC's location for the map origin (Settings › Location, default Abu Dhabi).</summary>
public static class AppLocation
{
    public static OriginCity Load()
    {
        var o = AppSettingsFile.Read();
        try
        {
            var city = o["originCity"]?.GetValue<string>();
            var lat = o["originLat"]?.GetValue<double>();
            var lon = o["originLon"]?.GetValue<double>();
            if (city != null && lat.HasValue && lon.HasValue)
                return new OriginCity(city, o["originCountry"]?.GetValue<string>() ?? "", lat.Value, lon.Value);
        }
        catch { }
        return CityCatalog.Default;
    }

    public static void Save(OriginCity c) => AppSettingsFile.Update(o =>
    {
        o["originCity"] = c.Name;
        o["originCountry"] = c.Country;
        o["originLat"] = c.Lat;
        o["originLon"] = c.Lon;
    });
}

/// <summary>
/// System | Light | Dark (graphite) | Midnight. One place that switches the WPF-UI base theme,
/// the app palette dictionary and the window chrome — live, no restart.
/// </summary>
public static class ThemeManager
{
    private const string PaletteBase = "pack://application:,,,/Themes/";
    private static string _paletteName = "Graphite";
    private static bool _hooked;

    public static string Current { get; private set; } = "Dark";

    /// <summary>Raised after a theme switch, so open pages can restyle anything they own.</summary>
    public static event Action? Changed;

    public static void ApplyInitial()
    {
        Current = ThemeSettings.Load();
        ApplyBase(Current);
        MergePaletteFor(ApplicationThemeManager.GetAppTheme() == ApplicationTheme.Dark);
        ThemeSettings.Save(Current);
    }

    /// <summary>Switch theme live. <paramref name="window"/> (optional) is re-skinned for Midnight.</summary>
    public static void Apply(string theme, Window? window)
    {
        Current = Normalize(theme);
        ApplyBase(Current);
        MergePaletteFor(ApplicationThemeManager.GetAppTheme() == ApplicationTheme.Dark);
        ApplyWindowChrome(window, Current);
        ThemeSettings.Save(Current);
        Changed?.Invoke();
    }

    private static void ApplyBase(string theme)
    {
        // SPEC-GLASS G1: acrylic preferred, Mica fallback, solid (None) when
        // "Transparency effects" is off (or on Windows 10, where the DWM call fails).
        var backdrop = PickBackdrop();
        try
        {
            switch (theme)
            {
                case "Light":
                    ApplicationThemeManager.Apply(ApplicationTheme.Light, backdrop);
                    break;
                case "Midnight":
                    ApplicationThemeManager.Apply(ApplicationTheme.Dark, WindowBackdropType.None);
                    break;
                case "Aurora":
                    // The ink colour now comes from the drifting glow layer (GlowLayer); with a
                    // live backdrop the root panel stays transparent so the glass shows through.
                    ApplicationThemeManager.Apply(ApplicationTheme.Dark, backdrop);
                    break;
                default: // System / Dark
                    ApplicationThemeManager.ApplySystemTheme();
                    ApplicationThemeManager.Apply(
                        ApplicationThemeManager.GetAppTheme() == ApplicationTheme.Dark
                            ? ApplicationTheme.Dark
                            : ApplicationTheme.Light,
                        backdrop);
                    break;
            }
        }
        catch (Exception ex)
        {
            try { IpcServer.LogFailure("ui.theme/backdrop", ex); } catch { }
            // Fall back to the plain theme without a backdrop.
            try
            {
                if (theme == "Light") ApplicationThemeManager.Apply(ApplicationTheme.Light, WindowBackdropType.None);
                else if (theme == "System") ApplicationThemeManager.ApplySystemTheme();
                else ApplicationThemeManager.Apply(ApplicationTheme.Dark, WindowBackdropType.None);
            }
            catch { /* theme application is best-effort */ }
        }
    }

    /// <summary>Acrylic first, Mica fallback, solid (None) when the user has turned off
    /// "Transparency effects" (SPEC-GLASS G1). On Windows 10 the Mica DWM call fails
    /// internally and the window stays solid — the chain is acrylic → mica → solid.</summary>
    public static WindowBackdropType PickBackdrop()
    {
        if (!TransparencyEffectsOn())
            return WindowBackdropType.None;
        return IsWindows11() ? WindowBackdropType.Acrylic : WindowBackdropType.Mica;
    }

    private static bool TransparencyEffectsOn()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("EnableTransparency") is not int v || v != 0;
        }
        catch
        {
            return true; // unknown → Windows 11 default
        }
    }

    private static bool IsWindows11()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"Software\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue("CurrentBuildNumber") is string s
                && int.TryParse(s, out var b) && b >= 22000;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Merge the palette dictionary matching the effective light/dark state (Midnight wins).</summary>
    public static void MergePaletteFor(bool dark)
    {
        _paletteName = Current == "Midnight" || Current == "Aurora" ? Current : (dark ? "Graphite" : "Light");
        MergePalette(_paletteName);
        // WPF-UI swaps its own theme dictionaries after a theme change, which would otherwise
        // re-assert its card/background brushes over ours — re-merge so the app palette stays last.
        if (!_hooked)
        {
            _hooked = true;
            ApplicationThemeManager.Changed += (_, _) => MergePalette(_paletteName);
        }
    }

    private static void MergePalette(string name)
    {
        // A missing palette file must not crash (SPEC-GLASS 0.3): load first, swap only on success.
        ResourceDictionary next;
        try
        {
            next = new ResourceDictionary { Source = new Uri(PaletteBase + name + ".xaml", UriKind.Absolute) };
        }
        catch (Exception ex)
        {
            try { IpcServer.LogFailure("ui.theme/palette", ex); } catch { /* logging must not throw */ }
            return; // keep the previous palette
        }

        var dicts = Application.Current.Resources.MergedDictionaries;
        for (int i = dicts.Count - 1; i >= 0; i--)
        {
            var src = dicts[i].Source;
            if (src != null && src.OriginalString.StartsWith(PaletteBase, StringComparison.OrdinalIgnoreCase))
                dicts.RemoveAt(i); // drop the previous palette, then add the new one last (last wins)
        }
        dicts.Add(next);
        // SPEC-GLASS G2: keep the cached blurred-aurora snapshot across palette switches.
        if (GlassState.BackdropImage != null && next.Contains("GlassAuroraBackdropBrush")
            && next["GlassAuroraBackdropBrush"] is System.Windows.Media.ImageBrush ib)
            ib.ImageSource = GlassState.BackdropImage;
    }

    /// <summary>Re-skin a window: Midnight gets the navy gradient + 1 px border on its root panel.</summary>
    public static void ApplyWindowChrome(Window? w, string theme)
    {
        if (w == null) return;
        if (w is Wpf.Ui.Controls.FluentWindow fw)
        {
            // Midnight paints its own navy gradient (below) — no backdrop behind it.
            fw.WindowBackdropType = theme == "Midnight" ? WindowBackdropType.None : PickBackdrop();
            fw.WindowCornerPreference = Wpf.Ui.Controls.WindowCornerPreference.Round;
        }
        // FluentWindow's own template paints the client area, so Window.Background alone is not
        // enough — the app's root panel carries the theme background (Mica stays visible otherwise).
        if (w.Content is DependencyObject root && root is Panel panel)
        {
            // SPEC-GLASS G1: Midnight always paints; Aurora paints its ink only when there is
            // no live backdrop — with a backdrop the panel stays transparent and the drifting
            // glow layer (GlowLayer) carries the colour.
            bool backdropLive = theme != "Midnight" && PickBackdrop() != WindowBackdropType.None;
            bool painted = theme == "Midnight" || (theme == "Aurora" && !backdropLive);
            if (painted && TryGetBrush("AppWindowBackgroundBrush") is Brush bg)
                panel.Background = bg;
            else
                panel.ClearValue(Panel.BackgroundProperty);
        }
        if (theme == "Midnight" || theme == "Aurora")
        {
            w.BorderBrush = TryGetBrush("AppWindowBorderBrush");
            w.BorderThickness = new Thickness(1);
        }
        else
        {
            w.ClearValue(Window.BackgroundProperty);
            w.ClearValue(Window.BorderBrushProperty);
            w.BorderThickness = new Thickness(0);
        }
    }

    /// <summary>A missing theme key must not crash the app (SPEC-GLASS 0.3):
    /// Resources[key] throws KeyNotFoundException on a missing key.</summary>
    internal static Brush? TryGetBrush(string key)
    {
        return Application.Current.Resources.Contains(key)
            ? Application.Current.Resources[key] as Brush
            : null;
    }

    public static string Normalize(string? t)
    {
        if (t == "Light") return "Light";
        if (t == "Midnight") return "Midnight";
        if (t == "Aurora") return "Aurora";
        if (t == "System") return "System";
        return "Dark";
    }

    /// <summary>Display name for the Settings picker.</summary>
    public static string Describe(string t)
    {
        if (t == "Aurora") return "Aurora (default)";
        if (t == "Light") return "Light";
        if (t == "Midnight") return "Midnight";
        if (t == "System") return "System (follow Windows)";
        return "Dark (graphite)";
    }
}

/// <summary>Persists the chosen theme in %LOCALAPPDATA%\OutboundWin\settings.json.</summary>
public static class ThemeSettings
{
    public static string Load()
    {
        try
        {
            var t = AppSettingsFile.Read()["theme"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(t)) return ThemeManager.Normalize(t);
        }
        catch { }
        return "Aurora"; // default since the Aurora redesign
    }

    public static void Save(string theme) =>
        // Merge, don't clobber: location and policy settings live in the same file.
        AppSettingsFile.Update(o => o["theme"] = ThemeManager.Normalize(theme));
}

using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Outbound.Core.Engine;
using Outbound.Core.Policy;
using Outbound.Core.Rules;

namespace Outbound.App;

/// <summary>Flyout panel shown from the tray icon (Phase 3 item 2).</summary>
public partial class TrayFlyout : UserControl
{
    private MainWindow? _host;
    private int _modeIndex;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private DateTime _resumeAt = DateTime.MinValue;

    public TrayFlyout() => InitializeComponent();

    public sealed record RecentItem(string Mark, string AppName, string Host);

    /// <summary>Called once from MainWindow after the engine/policy exist.</summary>
    public void Wire(MainWindow host)
    {
        _host = host;
        BtnOpen.Click += (_, _) => host.ShowFromTray();
        BtnCompact.Click += (_, _) => host.ToggleCompact(); // compact live Activity window
        ModeLearn.Click += (_, _) => SetMode(Mode.Learn);
        ModeAsk.Click += (_, _) => SetMode(Mode.Ask);
        ModeStrict.Click += (_, _) => SetMode(Mode.Strict);
        // G3: keep the glass segment thumb aligned through first layout + resizes.
        ModeSegHost.SizeChanged += (_, _) => SlideThumb(animate: false);
        BtnPause.Click += (_, _) => TogglePauseOrResume();
        BtnOff.Click += (_, _) => TurnOff();
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Refresh();
    }

    private void SetMode(Mode m)
    {
        if (_host == null) return;
        _host.Policy.Engine.Settings.Mode = m;
        UpdateModeButtons(m);
        SlideThumb(animate: true); // user clicked: slide the glass thumb
        RefreshStatus();
    }

    private void TogglePauseOrResume()
    {
        if (_host == null) return;
        bool enabled = _host.Policy.Enabled;
        if (enabled)
        {
            // Pause 15 min: auto-resume.
            _host.Policy.Enabled = false;
            _resumeAt = DateTime.UtcNow.AddMinutes(15);
            BtnPause.Content = "Resume";
        }
        else
        {
            Resume();
        }
        RefreshStatus();
    }

    private void TurnOff()
    {
        if (_host == null) return;
        _host.Policy.Enabled = false;
        _resumeAt = DateTime.MinValue; // no auto-resume
        BtnPause.Content = "Resume";
        RefreshStatus();
    }

    private void Resume()
    {
        if (_host == null) return;
        _host.Policy.Enabled = true;
        _resumeAt = DateTime.MinValue;
        BtnPause.Content = "Pause 15 min";
        RefreshStatus();
    }

    private void Tick()
    {
        // Auto-resume after a timed pause.
        if (_host != null && !_host.Policy.Enabled && _resumeAt > DateTime.MinValue && DateTime.UtcNow >= _resumeAt)
            Resume();
        Refresh();
    }

    private void UpdateModeButtons(Mode m)
    {
        _modeIndex = m == Mode.Learn ? 0 : m == Mode.Ask ? 1 : 2;
        ModeLearn.IsChecked = m == Mode.Learn;
        ModeAsk.IsChecked = m == Mode.Ask;
        ModeStrict.IsChecked = m == Mode.Strict;
    }

    /// <summary>Positions/slides the G3 glass segment thumb to the current mode.</summary>
    private void SlideThumb(bool animate)
    {
        if (ModeSegHost is null || ModeThumb is null) return;
        GlassSeg.SlideTo(ModeSegHost, ModeThumb, _modeIndex, 3, animate);
    }

    private void RefreshStatus()
    {
        if (_host == null) return;
        string mode = ModeNames.Of(_host.Policy.Engine.Settings.Mode);
        bool enabled = _host.Policy.Enabled;
        StatusLine.Text = !enabled
            ? (_resumeAt > DateTime.MinValue
                ? $"Paused until {_resumeAt.ToLocalTime():HH:mm} · {mode}"
                : "Turned off · not checking connections")
            : $"OutGate is on · {mode} — checking every connection";
    }

    private void Refresh()
    {
        if (_host == null) return;
        RefreshStatus();
        UpdateModeButtons(_host.Policy.Engine.Settings.Mode);

        var c = _host.Policy.Counts();
        CountsLine.Text = $"{c.Apps} apps · {c.Allowed} allowed · {c.Blocked} blocked";

        var recent = new List<RecentItem>();
        foreach (var f in _host.Engine.Snapshot().OrderByDescending(f => f.BytesRecv + f.BytesSent).Take(5))
            recent.Add(new RecentItem(
                f.Decision == "deny" ? "✗" : f.Decision == "allow" ? "✓" : "·",
                f.App.DisplayName, f.DisplayHost));
        RecentList.ItemsSource = recent;
    }
}

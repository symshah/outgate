using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace Outbound.App;

/// <summary>
/// Compact live Activity feed (SPEC-UI §2 compact window): one row per connection, newest first,
/// with a ✕/✓ decision pill that writes the same rule the CLI does.
/// A plain Window (not FluentWindow) so it can be opened/closed repeatedly.
/// </summary>
public partial class CompactWindow : Window
{
    private readonly MainWindow _owner;
    private readonly DispatcherTimer _timer;
    private readonly ObservableCollection<CompactRowVm> _rows = [];
    private readonly HashSet<string> _seenKeys = [];
    private string _filter = "";
    private bool _restoring;

    public CompactWindow(MainWindow owner)
    {
        InitializeComponent();
        _owner = owner;
        RowsHost.ItemsSource = _rows;
        TxtSearch.TextChanged += (_, _) => UpdatePlaceholder();

        Loaded += (_, _) =>
        {
            RestoreBounds();
            ThemeManager.ApplyWindowChrome(this, ThemeManager.Current);
            SetPinned(LoadPinned());
            Refresh();
        };
        LocationChanged += (_, _) => SaveBoundsSoon();
        SizeChanged += (_, _) => SaveBoundsSoon();
        Closing += (_, _) => SaveBounds();
        Closed += (_, _) => _timer.Stop();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
    }

    // ---------- data ----------

    private void Refresh()
    {
        if (_owner is null) return;
        List<CompactRowVm> feed;
        try { feed = _owner.BuildCompactRows(120); }
        catch { return; }

        // Drop rows that vanished from the feed, keep the rest in place so only new rows animate.
        var wanted = new HashSet<string>(feed.Select(r => r.Key));
        for (int i = _rows.Count - 1; i >= 0; i--)
            if (!wanted.Contains(_rows[i].Key)) _rows.RemoveAt(i);

        foreach (var row in feed)
        {
            if (_seenKeys.Contains(row.Key))
            {
                var existing = _rows.FirstOrDefault(r => r.Key == row.Key);
                if (existing != null) { existing.Ago = row.Ago; existing.Decision = row.Decision; existing.BytesDisplay = row.BytesDisplay; }
                continue;
            }
            _seenKeys.Add(row.Key);
            row.IsNew = true;
            _rows.Insert(0, row); // newest at the top
        }
        while (_rows.Count > 200) _rows.RemoveAt(_rows.Count - 1);

        ApplyFilter();
        SeenTodayText.Text = _owner.LastCompactTotal + " seen today";
        EmptyText.Visibility = _rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        AnimateNewRows();
    }

    private void ApplyFilter()
    {
        var view = CollectionViewSource.GetDefaultView(_rows);
        if (view == null) return;
        view.Filter = o =>
        {
            if (_filter.Length == 0) return true;
            if (o is not CompactRowVm r) return true;
            return r.AppName.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                || r.Host.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                || r.PortProto.Contains(_filter, StringComparison.OrdinalIgnoreCase);
        };
        view.Refresh();
    }

    // New rows slide in from the top (200 ms ease-out) — older rows are pushed down by the insert.
    private void AnimateNewRows()
    {
        Dispatcher.BeginInvoke(() =>
        {
            for (int i = 0; i < _rows.Count; i++)
            {
                if (!_rows[i].IsNew) continue;
                if (RowsHost.ItemContainerGenerator.ContainerFromIndex(i) is not FrameworkElement el) continue;
                _rows[i].IsNew = false;
                var slide = new TranslateTransform(0, -18);
                el.RenderTransform = slide;
                el.Opacity = 0;
                var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
                el.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200)) { EasingFunction = ease });
                slide.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(-18, 0, TimeSpan.FromMilliseconds(200)) { EasingFunction = ease });
            }
        }, DispatcherPriority.Loaded);
    }

    // ---------- decision pill ----------

    private void Allow_Click(object sender, RoutedEventArgs e) => Decide(sender, allow: true);
    private void Block_Click(object sender, RoutedEventArgs e) => Decide(sender, allow: false);

    private void Decide(object sender, bool allow)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not CompactRowVm row) return;
        bool ok = _owner.CreateRuleFromCompact(row, allow);
        if (!ok) return;
        row.Decision = allow ? CompactDecision.Allowed : CompactDecision.Blocked; // DataTemplate triggers fill the pill
        Refresh();
    }

    // ---------- chrome ----------

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) { WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized; return; }
        try { DragMove(); } catch { /* button released mid-drag */ }
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();

    private void BtnPin_Click(object sender, RoutedEventArgs e) => SetPinned(!Topmost);

    private void SetPinned(bool on)
    {
        Topmost = on;
        SavePinned(on);
    }

    private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        _filter = TxtSearch.Text.Trim();
        UpdatePlaceholder();
        ApplyFilter();
    }

    private void UpdatePlaceholder() =>
        SearchPlaceholder.Visibility = TxtSearch.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

    // ---------- bounds + prefs ----------

    private void RestoreBounds()
    {
        _restoring = true;
        try
        {
            var o = AppSettingsFile.Read();
            double x = o["compactX"]?.GetValue<double>() ?? double.NaN;
            double y = o["compactY"]?.GetValue<double>() ?? double.NaN;
            double w = o["compactW"]?.GetValue<double>() ?? 800;
            double h = o["compactH"]?.GetValue<double>() ?? 650;
            if (!double.IsNaN(x) && !double.IsNaN(y))
            {
                // keep it on a visible screen
                var vs = SystemParameters.VirtualScreenWidth; var vt = SystemParameters.VirtualScreenHeight;
                if (x < -40 || y < -40 || x > vs - 100 || y > vt - 100) { x = double.NaN; y = double.NaN; }
            }
            Width = Math.Max(MinWidth, w);
            Height = Math.Max(MinHeight, h);
            if (!double.IsNaN(x) && !double.IsNaN(y)) { Left = x; Top = y; }
            else { Left = SystemParameters.WorkArea.Right - Width - 40; Top = SystemParameters.WorkArea.Top + 60; }
        }
        catch { }
        finally { _restoring = false; }
    }

    private static bool LoadPinned()
    {
        try { return AppSettingsFile.Read()["compactTop"]?.GetValue<bool>() ?? false; } catch { return false; }
    }

    private static void SavePinned(bool on) => AppSettingsFile.Update(o => o["compactTop"] = on);

    private DateTime _lastBoundsSave = DateTime.MinValue;

    private void SaveBoundsSoon()
    {
        if (_restoring) return;
        if ((DateTime.UtcNow - _lastBoundsSave).TotalSeconds < 1.5) return;
        SaveBounds();
    }

    private void SaveBounds()
    {
        if (_restoring) return;
        _lastBoundsSave = DateTime.UtcNow;
        double x = Left, y = Top, w = Width, h = Height;
        if (WindowState != WindowState.Normal) return;
        AppSettingsFile.Update(o =>
        {
            o["compactX"] = x; o["compactY"] = y; o["compactW"] = w; o["compactH"] = h;
        });
    }
}

/// <summary>Decision state shown by the compact feed's pill.</summary>
public enum CompactDecision { Waiting, Allowed, Blocked }

/// <summary>One row of the compact Activity feed.</summary>
public sealed class CompactRowVm : System.ComponentModel.INotifyPropertyChanged
{
    public string Key { get; init; } = "";
    public string AppName { get; init; } = "";
    public string ExePath { get; init; } = "";
    public ImageSource? Icon { get; init; }
    public string Host { get; init; } = "";
    public string? Domain { get; init; }
    public ushort Port { get; init; }
    public string Proto { get; init; } = "";
    public string PortProto => Port + " · " + Proto.ToUpperInvariant();
    public string CountryCity { get; init; } = "";
    public bool IsLocal { get; init; }

    public string HostPrefix => Domain == null ? "" : (Host.Length > Domain.Length && Host.EndsWith(Domain, StringComparison.OrdinalIgnoreCase) ? Host[..^Domain.Length] : "");
    public string HostMain => Domain ?? Host;
    public string HostSuffix => "";

    private string _ago = "";
    public string Ago { get => _ago; set { if (_ago == value) return; _ago = value; Raise(nameof(Ago)); } }

    private string _bytes = "";
    public string BytesDisplay { get => _bytes; set { if (_bytes == value) return; _bytes = value; Raise(nameof(BytesDisplay)); } }

    private CompactDecision _decision = CompactDecision.Waiting;
    /// <summary>Drives the pill's visual state (DataTemplate triggers listen to this).</summary>
    public CompactDecision Decision { get => _decision; set { if (_decision == value) return; _decision = value; Raise(nameof(Decision)); } }

    internal bool IsNew { get; set; }
    internal DateTime SortUtc { get; init; }

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    private void Raise(string name) => PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
}

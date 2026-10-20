using System.Text;
using System.Windows;
using Outbound.Core.Policy;

namespace Outbound.App;

/// <summary>
/// "Network not working?" (SPEC Phase 3): current state, Pause 15 min / Turn off, and a summary
/// of recent blocked hosts with one-click Allow. Minimal v1 — the recent-blocks list is summarized
/// into a text block; per-host allow buttons land with the full Review wiring.
/// </summary>
public partial class HelpWindow : Window
{
    private readonly MainWindow _main;

    public HelpWindow(MainWindow main)
    {
        InitializeComponent();
        _main = main;
        Loaded += (_, _) => Refresh();
        Body.TextWrapping = System.Windows.TextWrapping.Wrap;
    }

    private void Refresh()
    {
        int blocked = _main.Policy.ReviewItems().Count(i => i.Action == ReviewAction.Blocked);
        var recent = _main.Policy.ReviewItems()
            .Where(i => i.Action == ReviewAction.Blocked)
            .OrderByDescending(i => i.SeenUtc).Take(6).ToList();
        var sb = new StringBuilder();
        sb.Append("Blocked in the last 30 minutes: ").Append(blocked).Append("\n\n");
        foreach (var i in recent)
            sb.Append("• ").Append(i.AppName).Append(" → ").Append(i.Host ?? i.RemoteIp).Append("\n");
        if (recent.Count == 0) sb.Append("Nothing blocked recently.");
        Body.Text = sb.ToString();
    }

    private void BtnPause_Click(object sender, RoutedEventArgs e)
    {
        _main.Policy.Enabled = false;
        new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMinutes(15) }.Start();
        Body.Text = "OutGate is paused for 15 minutes.";
    }

    private void BtnOff_Click(object sender, RoutedEventArgs e)
    {
        _main.Policy.Enabled = false;
        Body.Text = "OutGate is turned off (policy evaluation stopped, no firewall changes).";
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();
}
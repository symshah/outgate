using System.Windows;

namespace Outbound.App;

/// <summary>
/// Phase 5 item 2: approval dialog for MCP rule changes. The pipe thread blocks until this
/// window is answered (Approve / Deny / X) or the countdown expires — auto-deny on timeout,
/// so an unattended agent can never change rules silently. Enter/Esc never answer it.
/// </summary>
public partial class ApprovalWindow : Window
{
    public bool Approved { get; private set; }

    private readonly System.Windows.Threading.DispatcherTimer _tick;
    private DateTime _expiresUtc;

    public ApprovalWindow(string description, int timeoutSeconds)
    {
        InitializeComponent();
        DescText.Text = description;
        _expiresUtc = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        BtnApprove.IsEnabled = false;
        BtnDeny.IsEnabled = false;
        _tick = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _tick.Tick += (_, _) => Tick();
        _tick.Start();
    }

    private void Tick()
    {
        var left = _expiresUtc - DateTime.UtcNow;
        if (left <= TimeSpan.Zero) { Approved = false; Close(); return; } // auto-deny on timeout
        CountdownLine.Text = "Auto-denied in " + Math.Max(0, (int)left.TotalSeconds) + " s if not answered.";
        if (!BtnApprove.IsEnabled) { BtnApprove.IsEnabled = true; BtnDeny.IsEnabled = true; } // enable after first tick (~1 s)
    }

    private void Approve_Click(object sender, RoutedEventArgs e) { Approved = true; Close(); }
    private void Deny_Click(object sender, RoutedEventArgs e) { Approved = false; Close(); }
}

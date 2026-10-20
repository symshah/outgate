using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Outbound.Core.Domains;
using Outbound.Core.Engine;
using Outbound.Core.Identity;
using Outbound.Core.Policy;
using Outbound.Core.Rules;

namespace Outbound.App;

/// <summary>
/// The "question" window (SPEC Phase 3): one pending Ask prompt at a time, side queue of the rest.
/// Deny/Allow enable only after ~1 s so a stray keystroke can't decide; Enter/Esc never answer it.
/// </summary>
public partial class AskWindow : Window
{
    private readonly PolicyService _policy;
    private PendingAsk? _current;
    private LifetimeKind _lifetime = LifetimeKind.Forever; // SPEC default
    private string _scope = "port";                        // SPEC default: this port only
    private bool _answered;
    private System.Windows.Threading.DispatcherTimer? _tick;

    public AskWindow(PolicyService policy)
    {
        InitializeComponent();
        _policy = policy;
        Loaded += (_, _) => ShowNext();
        Closed += (_, _) => _tick?.Stop();
    }

    /// <summary>UI-thread: a prompt was added, answered or timed out — show the next pending one (or close).</summary>
    public void Refresh()
    {
        if (!IsLoaded) return;
        if (_answered) return; // this window's flow was just answered — closing
        bool stillPending = _current != null && _policy.Prompts.All().Any(a => a.ReviewId == _current!.ReviewId);
        if (!stillPending) ShowNext();
    }

    private void ShowNext()
    {
        var next = _policy.Prompts.All().OrderBy(a => a.AskedAt).FirstOrDefault();
        if (next == null) { Close(); return; }
        _current = next;
        _answered = false;
        Populate(next);
        UpdateQueue();

        // Reset the pickers to their defaults for each new question.
        LifeForever.IsChecked = true;   // fires Life_Checked → _lifetime
        ScopePort.IsChecked = true;     // fires Scope_Checked → _scope

        BtnDeny.IsEnabled = false;
        BtnAllow.IsEnabled = false;
        _tick?.Stop();
        var startedAt = DateTime.UtcNow;
        _tick = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _tick.Tick += (_, _) =>
        {
            if (_current != next || _answered) return;
            UpdateCountdown();
            // Buttons enable only after ~1 s.
            if (DateTime.UtcNow - startedAt >= TimeSpan.FromSeconds(1))
            {
                BtnDeny.IsEnabled = true;
                BtnAllow.IsEnabled = true;
            }
        };
        _tick.Start();
    }

    private void Populate(PendingAsk a)
    {
        var ctx = a.Ctx;
        AppName.Text = ctx.ProcessName;
        try { AppIcon.Source = LoadAppIcon(ctx.ExePath); } catch { AppIcon.Source = null; }

        // Signer line — unsigned is highlighted.
        var signer = SafeSigner(ctx.Pid, ctx.ExePath);
        if (signer.Kind == SignerKind.Unsigned)
        {
            SignerLine.Text = "Unsigned";
            SignerLine.Foreground = System.Windows.Media.Brushes.Crimson;
        }
        else
        {
            SignerLine.Text = $"Signed by {signer.Publisher}";
            SignerLine.Foreground = System.Windows.Media.Brushes.DimGray;
        }

        // Destination: registrable domain bold so look-alikes stand out.
        string? host = ctx.Host;
        string? main = PublicSuffixList.Default?.RegistrableDomain(host ?? "");
        if (main != null && !string.Equals(main, host, StringComparison.OrdinalIgnoreCase))
        {
            int i = host!.IndexOf(main, StringComparison.OrdinalIgnoreCase);
            DestSub.Text = host[..i];
            DestMain.Text = host[i..];
        }
        else { DestSub.Text = ""; DestMain.Text = host ?? ctx.RemoteIp; }

        PortLine.Text = $"{ctx.RemotePort} · {ProtoName(ctx.Proto)}{ServiceSuffix((int)ctx.RemotePort, ctx.Proto)}";

        // Publisher note: does the host belong to the app's own publisher?
        if (main != null && signer.Publisher != null)
            PublisherNote.Text = main.Contains(signer.Publisher.Split(' ')[0], StringComparison.OrdinalIgnoreCase)
                ? $"This domain looks related to {signer.Publisher}."
                : "Unrecognised — this host is not associated with the app's publisher.";
        else PublisherNote.Text = "";

        UpdateCountdown();
    }

    private void UpdateCountdown()
    {
        if (_current == null) return;
        var left = _current.ExpiresAt - DateTime.UtcNow;
        string outcome = _policy.Engine.Settings.BlockWhenPromptUnanswered ? "it will be blocked" : "it will be allowed";
        CountdownLine.Text = $"If you don't answer in {Math.Max(0, (int)left.TotalSeconds)} s, {outcome}.";
    }

    private void UpdateQueue()
    {
        var all = _policy.Prompts.All().Where(a => a.ReviewId != _current?.ReviewId).OrderBy(a => a.AskedAt).ToList();
        QueueTitle.Text = $"Waiting ({all.Count})";
        QueueList.ItemsSource = all.Select(a => $"{a.Ctx.ProcessName} → {a.Ctx.Host ?? a.Ctx.RemoteIp}").ToList();
        BtnAnswerAll.IsEnabled = _current != null && all.Any(x => x.AppKey == _current!.AppKey);
    }

    private void Life_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton b && Enum.TryParse<LifetimeKind>(b.Tag as string, out var k)) _lifetime = k;
    }

    private void Scope_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton b && b.Tag is string s) _scope = s;
    }

    private void Allow_Click(object sender, RoutedEventArgs e) => Answer(RuleAction.Allow);
    private void Deny_Click(object sender, RoutedEventArgs e) => Answer(RuleAction.Deny);

    private void AnswerAll_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null || _answered) return;
        foreach (var a in _policy.Prompts.All().Where(a => a.AppKey == _current!.AppKey).ToList())
            _policy.Answer(a.ReviewId, RuleAction.Allow, _lifetime, _scope, a.Ctx.Pid);
        _answered = true;
        Close();
    }

    private void Answer(RuleAction action)
    {
        if (_current == null || _answered) return;
        _policy.Answer(_current.ReviewId, action, _lifetime, _scope, _current.Ctx.Pid);
        _answered = true;
        Close();
    }

    private static SignerInfo SafeSigner(int pid, string exePath)
    {
        try { return AppResolver.Resolve(pid).Signer; } catch { return SignerInfo.None; }
    }

    private static ImageSource? LoadAppIcon(string exePath)
    {
        if (string.IsNullOrEmpty(exePath)) return null;
        var icon = System.Drawing.Icon.ExtractAssociatedIcon(exePath);
        if (icon == null) return null;
        using var ms = new System.IO.MemoryStream();
        icon.Save(ms);
        ms.Position = 0;
        var bmp = new BitmapImage();
        bmp.BeginInit();
        bmp.CacheOption = BitmapCacheOption.OnLoad;
        bmp.StreamSource = ms;
        bmp.EndInit();
        return bmp;
    }

    private static string ProtoName(ProtoSpec p) => p switch { ProtoSpec.Tcp => "TCP", ProtoSpec.Udp => "UDP", _ => "" };

    /// <summary>"443 TCP HTTPS" — well-known service names only, no network lookup.</summary>
    private static string ServiceSuffix(int port, ProtoSpec proto)
    {
        if (proto == ProtoSpec.Tcp && port is 80) return " · HTTP";
        if (port is 443) return " · HTTPS";
        if (port is 53) return " · DNS";
        if (port is 22) return " · SSH";
        if (port is 3389) return " · RDP";
        return "";
    }
}

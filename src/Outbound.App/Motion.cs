using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace Outbound.App;

/// <summary>
/// LocalDoc-style motion: pages fade and rise in, glass cards stagger in one after another with
/// a springy overshoot, and cards lift on hover. Everything is skipped when Windows has
/// "Animate windows" off, and every call is wrapped so a visual-only failure never breaks the UI.
/// </summary>
public static class Motion
{
    private static readonly IEasingFunction Smooth = new CubicEase { EasingMode = EasingMode.EaseOut };
    private static readonly IEasingFunction Spring = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.55 };

    public static bool Enabled => SystemParameters.ClientAreaAnimation;

    /// <summary>Fade + rise the whole page, then stagger its glass cards (45 ms apart).</summary>
    public static void PageIn(FrameworkElement page)
    {
        if (!Enabled || page is null) return;
        try
        {
            Rise(page, 16, 380, 0, fade: true);

            var cards = new List<Border>();
            Collect(page, cards);
            int i = 0;
            foreach (var card in cards)
            {
                if (i >= 10) break;                 // never delay a long list
                Rise(card, 22, 520, 60 + i * 45, fade: true);
                i++;
            }
        }
        catch { /* visual-only */ }
    }

    /// <summary>Lift a card 3 px on hover with a spring, settle back on leave.</summary>
    public static void HoverLift(Border card)
    {
        if (card.Tag is "motion-hover") return;
        card.Tag = "motion-hover";
        EnsureTranslate(card);
        card.MouseEnter += (_, _) => Lift(card, -3);
        card.MouseLeave += (_, _) => Lift(card, 0);
    }

    private static void Lift(Border card, double y)
    {
        if (!Enabled || card.RenderTransform is not TranslateTransform tt) return;
        tt.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(y, TimeSpan.FromMilliseconds(260)) { EasingFunction = Spring });
    }

    private static void Rise(FrameworkElement el, double fromY, int ms, int delayMs, bool fade)
    {
        var tt = EnsureTranslate(el);
        var t = TimeSpan.FromMilliseconds(delayMs);
        var move = new DoubleAnimation(fromY, 0, TimeSpan.FromMilliseconds(ms))
            { BeginTime = t, EasingFunction = Spring };
        tt.BeginAnimation(TranslateTransform.YProperty, move);
        if (fade)
        {
            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(Math.Max(240, ms - 120)))
                { BeginTime = t, EasingFunction = Smooth, FillBehavior = FillBehavior.Stop };
            el.BeginAnimation(UIElement.OpacityProperty, fadeIn);
        }
    }

    private static TranslateTransform EnsureTranslate(UIElement el)
    {
        if (el.RenderTransform is TranslateTransform tt && !tt.IsFrozen) return tt;
        tt = new TranslateTransform();
        el.RenderTransform = tt;
        return tt;
    }

    // Glass cards are the Borders that carry the card shadow (rows and pills have none).
    private static void Collect(DependencyObject root, List<Border> into)
    {
        int n = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < n; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is Border b && b.Effect is not null && b.CornerRadius.TopLeft >= 18)
            {
                into.Add(b);
                HoverLift(b);
                continue;                           // don't descend into a card
            }
            Collect(child, into);
        }
    }
}

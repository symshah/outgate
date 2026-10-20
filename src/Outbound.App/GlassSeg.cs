using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace Outbound.App;

/// <summary>
/// Drives the sliding "liquid" thumb of a G3 glass segmented control (SPEC-GLASS G3).
/// The thumb is a Border with HorizontalAlignment=Left and a TranslateTransform;
/// <see cref="SlideTo"/> animates its width + X to the chosen equal-width column with a
/// ~250 ms BackEase. The animation is skipped (instant jump) when Windows has
/// "Animate windows" off (<see cref="SystemParameters.ClientAreaAnimation"/>) or before the
/// first layout pass, so it respects the OS setting.
/// </summary>
public static class GlassSeg
{
    private static readonly Duration Slide = new(TimeSpan.FromMilliseconds(250));

    /// <summary>
    /// Slide <paramref name="thumb"/> to column <paramref name="index"/> of
    /// <paramref name="count"/> equal-width segments inside <paramref name="host"/>.
    /// </summary>
    /// <param name="host">The inner Grid that holds the equal-width segment columns.</param>
    /// <param name="thumb">The sliding Border (HorizontalAlignment=Left, VerticalAlignment=Stretch, a TranslateTransform as RenderTransform).</param>
    /// <param name="index">Target column, 0-based.</param>
    /// <param name="count">Total number of columns.</param>
    /// <param name="animate">Slide with BackEase; false = instant jump (used for layout/resize).</param>
    public static void SlideTo(FrameworkElement host, FrameworkElement thumb, int index, int count, bool animate)
    {
        if (host is null || thumb is null || count <= 0) return;
        index = Math.Clamp(index, 0, count - 1);

        double colW = host.ActualWidth / count;
        double targetX = index * colW;

        bool canAnimate = animate
            && SystemParameters.ClientAreaAnimation
            && host.ActualWidth > 0;

        if (!canAnimate)
        {
            // Instant jump: OS animation off, or not laid out yet.
            thumb.Width = colW;
            if (thumb.RenderTransform is TranslateTransform tt)
                tt.X = targetX;
            return;
        }

        var ease = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.6 };
        thumb.BeginAnimation(FrameworkElement.WidthProperty,
            new DoubleAnimation(colW, Slide) { EasingFunction = ease });
        if (thumb.RenderTransform is TranslateTransform ttx)
            ttx.BeginAnimation(TranslateTransform.XProperty,
                new DoubleAnimation(targetX, Slide) { EasingFunction = ease });
    }
}

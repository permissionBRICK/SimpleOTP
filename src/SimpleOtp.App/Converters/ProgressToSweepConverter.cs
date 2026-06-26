using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace SimpleOtp.App.Converters;

/// <summary>
/// Converts a 0..1 progress value to an <see cref="Avalonia.Controls.Shapes.Arc"/> sweep angle in
/// degrees. Negative sweep = clockwise; we clamp just under a full turn so a "full" ring still
/// renders (an exact -360° draws nothing).
/// </summary>
public sealed class ProgressToSweepConverter : IValueConverter
{
    public static readonly ProgressToSweepConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        double progress = Math.Clamp(value is double d ? d : 0d, 0d, 1d);
        return -359.999d * progress;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

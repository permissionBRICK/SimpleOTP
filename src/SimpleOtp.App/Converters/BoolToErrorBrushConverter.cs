using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace SimpleOtp.App.Converters;

/// <summary>True → error red, false → neutral info gray. Used for status messages.</summary>
public sealed class BoolToErrorBrushConverter : IValueConverter
{
    private static readonly IBrush Error = new SolidColorBrush(Color.Parse("#F2685C"));
    private static readonly IBrush Info = new SolidColorBrush(Color.Parse("#9AA0AA"));

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? Error : Info;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

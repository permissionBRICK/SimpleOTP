using System;
using System.Collections.Generic;
using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;

namespace SimpleOtp.App.Markdown;

/// <summary>
/// Renders the <see cref="MarkdownParser"/> model into a themed Avalonia control tree for the update
/// popup's release notes. Colors match the dark UI used elsewhere. Links to http(s) URLs are clickable
/// (opened in the system browser); any other scheme is shown as styled, non-clickable text so the popup
/// can never be turned into a launcher for an arbitrary URI.
/// </summary>
internal static class MarkdownRenderer
{
    private static readonly IBrush Body = Brush("#C9CDD4");
    private static readonly IBrush HeadingFg = Brush("#F2F3F5");
    private static readonly IBrush Muted = Brush("#8A8F99");
    private static readonly IBrush LinkFg = Brush("#6AA9FF");
    private static readonly IBrush CodeBg = Brush("#2A2C31");
    private static readonly IBrush CodeFg = Brush("#E7E9EC");
    private static readonly IBrush RuleFg = Brush("#33363D");
    private static readonly FontFamily Mono = new("Cascadia Code,Consolas,Menlo,monospace");

    private const double BodySize = 12;

    /// <summary>Builds a vertical stack of blocks from markdown text.</summary>
    public static Control Build(string? markdown)
    {
        var panel = new StackPanel { Spacing = 9 };
        foreach (MdBlock block in MarkdownParser.Parse(markdown))
            panel.Children.Add(RenderBlock(block));
        return panel;
    }

    private static Control RenderBlock(MdBlock block) => block switch
    {
        MdHeading h => Heading(h),
        MdList list => List(list),
        MdCode code => Code(code),
        MdRule => new Border { Height = 1, Background = RuleFg, Margin = new Thickness(0, 2, 0, 2) },
        MdParagraph p => Text(p.Inlines, BodySize, Body),
        _ => Text(new List<MdInline>(), BodySize, Body),
    };

    private static Control Heading(MdHeading h)
    {
        double size = h.Level switch { 1 => 17, 2 => 15, 3 => 13.5, _ => 12.5 };
        SelectableTextBlock tb = Text(h.Inlines, size, HeadingFg);
        tb.FontWeight = FontWeight.SemiBold;
        return tb;
    }

    private static Control List(MdList list)
    {
        var panel = new StackPanel { Spacing = 4 };
        foreach (MdListItem item in list.Items)
        {
            var grid = new Grid
            {
                Margin = new Thickness(item.Level * 16, 0, 0, 0),
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
            };
            var marker = new TextBlock
            {
                Text = item.Ordered is int n ? $"{n}." : "•",
                Foreground = Muted,
                FontSize = BodySize,
                Margin = new Thickness(0, 0, 8, 0),
                MinWidth = item.Ordered is null ? 0 : 16,
            };
            Grid.SetColumn(marker, 0);
            SelectableTextBlock content = Text(item.Inlines, BodySize, Body);
            Grid.SetColumn(content, 1);
            grid.Children.Add(marker);
            grid.Children.Add(content);
            panel.Children.Add(grid);
        }
        return panel;
    }

    private static Control Code(MdCode code) => new Border
    {
        Background = CodeBg,
        CornerRadius = new CornerRadius(6),
        Padding = new Thickness(10, 8),
        Child = new ScrollViewer
        {
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
            VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
            Content = new SelectableTextBlock
            {
                Text = code.Text,
                FontFamily = Mono,
                FontSize = BodySize,
                Foreground = CodeFg,
                TextWrapping = TextWrapping.NoWrap,
            },
        },
    };

    private static SelectableTextBlock Text(IReadOnlyList<MdInline> inlines, double size, IBrush color)
    {
        var tb = new SelectableTextBlock
        {
            FontSize = size,
            Foreground = color,
            TextWrapping = TextWrapping.Wrap,
        };
        foreach (MdInline inline in inlines)
            tb.Inlines!.Add(ToInline(inline));
        return tb;
    }

    private static Inline ToInline(MdInline inline)
    {
        switch (inline)
        {
            case MdText t:
                return new Run(t.Text);
            case MdBold b:
                return Fill(new Bold(), b.Inlines);
            case MdItalic it:
                return Fill(new Italic(), it.Inlines);
            case MdCodeSpan c:
                return new Run(c.Text) { FontFamily = Mono, Background = CodeBg, Foreground = CodeFg };
            case MdLink link:
                return Link(link);
            default:
                return new Run("");
        }
    }

    private static Inline Fill(Span span, IReadOnlyList<MdInline> inlines)
    {
        foreach (MdInline inline in inlines)
            span.Inlines.Add(ToInline(inline));
        return span;
    }

    private static Inline Link(MdLink link)
    {
        bool clickable = link.Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                      || link.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        var label = new TextBlock { Foreground = LinkFg, TextDecorations = TextDecorations.Underline };
        foreach (MdInline inner in link.Label)
            label.Inlines!.Add(ToInline(inner));

        if (clickable)
        {
            label.Cursor = new Cursor(StandardCursorType.Hand);
            ToolTip.SetTip(label, link.Url);
            label.PointerPressed += (_, _) => OpenUrl(link.Url);
        }

        return new InlineUIContainer { Child = label, BaselineAlignment = BaselineAlignment.TextBottom };
    }

    private static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { /* no browser available — nothing more we can do */ }
    }

    private static SolidColorBrush Brush(string hex) => new(Color.Parse(hex));
}

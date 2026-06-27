using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace SimpleOtp.App.Markdown;

/// <summary>
/// A small, dependency-free markdown parser covering the subset that shows up in GitHub release notes:
/// ATX headings, bullet/numbered lists, paragraphs, fenced code blocks and horizontal rules at the block
/// level; bold, italic, inline code and links at the inline level, plus backslash escapes and the few
/// HTML entities the release pipeline emits (e.g. <c>&amp;middot;</c>). It is intentionally forgiving —
/// anything it doesn't recognize falls through as literal text — so notes always render as readable text.
/// </summary>
internal static partial class MarkdownParser
{
    public static IReadOnlyList<MdBlock> Parse(string? markdown)
    {
        var blocks = new List<MdBlock>();
        string[] lines = (markdown ?? "").Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
        var paragraph = new List<string>();

        void FlushParagraph()
        {
            if (paragraph.Count == 0) return;
            // Single newlines inside a paragraph are soft wraps — join with a space.
            blocks.Add(new MdParagraph(ParseInlines(string.Join(" ", paragraph))));
            paragraph.Clear();
        }

        for (int i = 0; i < lines.Length;)
        {
            string line = lines[i];
            string trimmed = line.Trim();

            // Fenced code block: ``` ... ``` (the info string after the opening fence is ignored).
            if (trimmed.StartsWith("```"))
            {
                FlushParagraph();
                var code = new List<string>();
                i++;
                while (i < lines.Length && !lines[i].Trim().StartsWith("```"))
                    code.Add(lines[i++]);
                if (i < lines.Length) i++; // consume the closing fence
                blocks.Add(new MdCode(string.Join("\n", code)));
                continue;
            }

            if (trimmed.Length == 0)
            {
                FlushParagraph();
                i++;
                continue;
            }

            if (IsRule(trimmed))
            {
                FlushParagraph();
                blocks.Add(new MdRule());
                i++;
                continue;
            }

            Match heading = HeadingRegex().Match(trimmed);
            if (heading.Success)
            {
                FlushParagraph();
                blocks.Add(new MdHeading(heading.Groups[1].Value.Length, ParseInlines(heading.Groups[2].Value)));
                i++;
                continue;
            }

            if (TryMatchListItem(line, out int level, out int? ordered, out string content))
            {
                FlushParagraph();
                var items = new List<MdListItem>();
                while (i < lines.Length && TryMatchListItem(lines[i], out level, out ordered, out content))
                {
                    items.Add(new MdListItem(level, ordered, ParseInlines(content)));
                    i++;
                }
                blocks.Add(new MdList(items));
                continue;
            }

            paragraph.Add(trimmed);
            i++;
        }

        FlushParagraph();
        return blocks;
    }

    // --- Block helpers --------------------------------------------------------

    private static bool IsRule(string trimmed)
    {
        if (trimmed.Length < 3) return false;
        char c = trimmed[0];
        if (c != '-' && c != '*' && c != '_') return false;
        foreach (char ch in trimmed)
            if (ch != c) return false;
        return true;
    }

    private static bool TryMatchListItem(string line, out int level, out int? ordered, out string content)
    {
        level = 0;
        ordered = null;
        content = "";

        Match m = ListItemRegex().Match(line);
        if (!m.Success) return false;

        // Two spaces (or a tab) of indent per nesting level.
        string indent = m.Groups[1].Value.Replace("\t", "  ");
        level = indent.Length / 2;
        string marker = m.Groups[2].Value;
        if (marker is not ("-" or "*" or "+"))
            ordered = int.TryParse(marker.TrimEnd('.', ')'), out int num) ? num : 0;
        content = m.Groups[3].Value;
        return true;
    }

    // --- Inline parsing -------------------------------------------------------

    /// <summary>Parses a single line/paragraph of text into formatted inline spans.</summary>
    public static IReadOnlyList<MdInline> ParseInlines(string text)
    {
        var result = new List<MdInline>();
        var literal = new StringBuilder();

        void FlushLiteral()
        {
            if (literal.Length == 0) return;
            result.Add(new MdText(DecodeEntities(literal.ToString())));
            literal.Clear();
        }

        for (int i = 0; i < text.Length;)
        {
            char c = text[i];

            // Backslash escape: a backslash before ASCII punctuation emits that punctuation literally.
            if (c == '\\' && i + 1 < text.Length && IsAsciiPunctuation(text[i + 1]))
            {
                literal.Append(text[i + 1]);
                i += 2;
                continue;
            }

            // Inline code: `...` (no other formatting inside).
            if (c == '`')
            {
                int close = text.IndexOf('`', i + 1);
                if (close > i)
                {
                    FlushLiteral();
                    result.Add(new MdCodeSpan(text.Substring(i + 1, close - i - 1)));
                    i = close + 1;
                    continue;
                }
            }

            // Link: [label](url)
            if (c == '[' && TryParseLink(text, i, out MdLink? link, out int afterLink))
            {
                FlushLiteral();
                result.Add(link!);
                i = afterLink;
                continue;
            }

            // Bold: ** ... ** or __ ... __
            if ((c == '*' || c == '_') && i + 1 < text.Length && text[i + 1] == c
                && TryParseEmphasis(text, i, doubled: true, c, out string boldInner, out int afterBold))
            {
                FlushLiteral();
                result.Add(new MdBold(ParseInlines(boldInner)));
                i = afterBold;
                continue;
            }

            // Italic: * ... * or _ ... _
            if ((c == '*' || c == '_')
                && TryParseEmphasis(text, i, doubled: false, c, out string italicInner, out int afterItalic))
            {
                FlushLiteral();
                result.Add(new MdItalic(ParseInlines(italicInner)));
                i = afterItalic;
                continue;
            }

            literal.Append(c);
            i++;
        }

        FlushLiteral();
        return result;
    }

    private static bool TryParseLink(string text, int start, out MdLink? link, out int afterIndex)
    {
        link = null;
        afterIndex = start;

        // Find the ] that closes this [ (allowing nested brackets in the label).
        int depth = 0, labelEnd = -1;
        for (int k = start; k < text.Length; k++)
        {
            if (text[k] == '[') depth++;
            else if (text[k] == ']' && --depth == 0) { labelEnd = k; break; }
        }
        if (labelEnd < 0 || labelEnd + 1 >= text.Length || text[labelEnd + 1] != '(') return false;

        int urlStart = labelEnd + 2;
        int urlEnd = text.IndexOf(')', urlStart);
        if (urlEnd < 0) return false;

        string label = text.Substring(start + 1, labelEnd - start - 1);
        string url = text.Substring(urlStart, urlEnd - urlStart).Trim();
        link = new MdLink(ParseInlines(label), url);
        afterIndex = urlEnd + 1;
        return true;
    }

    private static bool TryParseEmphasis(string text, int start, bool doubled, char delim, out string inner, out int afterIndex)
    {
        inner = "";
        afterIndex = start;
        int delimLen = doubled ? 2 : 1;
        int contentStart = start + delimLen;
        if (contentStart >= text.Length || char.IsWhiteSpace(text[contentStart])) return false;
        // Underscores don't open emphasis mid-word (so snake_case and URLs survive).
        if (delim == '_' && start > 0 && char.IsLetterOrDigit(text[start - 1])) return false;

        for (int j = contentStart; j < text.Length; j++)
        {
            bool isClose = text[j] == delim && (!doubled || (j + 1 < text.Length && text[j + 1] == delim));
            if (!isClose) continue;
            int closeEnd = j + delimLen;
            if (char.IsWhiteSpace(text[j - 1])) continue; // closing run must not follow a space
            if (delim == '_' && closeEnd < text.Length && char.IsLetterOrDigit(text[closeEnd])) continue; // mid-word _

            if (j > contentStart)
            {
                inner = text.Substring(contentStart, j - contentStart);
                afterIndex = closeEnd;
                return true;
            }
        }
        return false;
    }

    private static bool IsAsciiPunctuation(char c) => c is (>= '!' and <= '/') or (>= ':' and <= '@')
        or (>= '[' and <= '`') or (>= '{' and <= '~');

    private static string DecodeEntities(string s)
    {
        if (s.IndexOf('&') < 0) return s;
        return s
            .Replace("&middot;", "·")
            .Replace("&bull;", "•")
            .Replace("&mdash;", "—")
            .Replace("&ndash;", "–")
            .Replace("&nbsp;", " ")
            .Replace("&lt;", "<")
            .Replace("&gt;", ">")
            .Replace("&quot;", "\"")
            .Replace("&#39;", "'")
            .Replace("&apos;", "'")
            .Replace("&amp;", "&"); // last, so "&amp;lt;" decodes to the literal "&lt;"
    }

    [GeneratedRegex(@"^(#{1,6})\s+(.*?)\s*#*$")]
    private static partial Regex HeadingRegex();

    // Leading indent, then a bullet (-, *, +) or an ordered marker (1. / 1)), then the content.
    [GeneratedRegex(@"^([ \t]*)([-*+]|\d{1,9}[.)])\s+(.*)$")]
    private static partial Regex ListItemRegex();
}

using System.Collections.Generic;
using System.Linq;
using System.Text;
using SimpleOtp.App.Markdown;

namespace SimpleOtp.Tests;

/// <summary>
/// Covers the markdown subset the update popup renders (GitHub release notes): bold/italic/code/link
/// inlines with escapes and HTML entities, and block-level headings, lists, fenced code and rules.
/// </summary>
public class MarkdownParserTests
{
    // Flattens an inline tree to its visible text, so a test can assert content without caring about nesting.
    private static string PlainText(IEnumerable<MdInline> inlines)
    {
        var sb = new StringBuilder();
        void Walk(IEnumerable<MdInline> items)
        {
            foreach (MdInline i in items)
            {
                switch (i)
                {
                    case MdText t: sb.Append(t.Text); break;
                    case MdCodeSpan c: sb.Append(c.Text); break;
                    case MdBold b: Walk(b.Inlines); break;
                    case MdItalic it: Walk(it.Inlines); break;
                    case MdLink l: Walk(l.Label); break;
                }
            }
        }
        Walk(inlines);
        return sb.ToString();
    }

    private static IReadOnlyList<MdInline> Inlines(string text) => MarkdownParser.ParseInlines(text);

    [Fact]
    public void PlainText_IsASingleTextRun()
    {
        var result = Inlines("just text");
        var text = Assert.IsType<MdText>(Assert.Single(result));
        Assert.Equal("just text", text.Text);
    }

    [Fact]
    public void Bold_Italic_And_Code_AreRecognized()
    {
        var bold = Inlines("a **strong** b");
        Assert.Collection(bold,
            i => Assert.Equal("a ", Assert.IsType<MdText>(i).Text),
            i => Assert.Equal("strong", PlainText(new[] { i })),
            i => Assert.Equal(" b", Assert.IsType<MdText>(i).Text));
        Assert.IsType<MdBold>(bold[1]);

        Assert.IsType<MdItalic>(Inlines("*soft*").Single());
        Assert.IsType<MdItalic>(Inlines("_soft_").Single());
        Assert.IsType<MdBold>(Inlines("__strong__").Single());

        var code = Assert.IsType<MdCodeSpan>(Inlines("`vault.json`").Single());
        Assert.Equal("vault.json", code.Text);
    }

    [Fact]
    public void Bold_CanContainInlineCode()
    {
        var bold = Assert.IsType<MdBold>(Inlines("**see `x`**").Single());
        Assert.Equal("see x", PlainText(new[] { (MdInline)bold }));
        Assert.Contains(bold.Inlines, i => i is MdCodeSpan);
    }

    [Fact]
    public void Underscores_InsideWords_AreNotEmphasis()
    {
        // snake_case and URLs must survive intact.
        var snake = Inlines("file_name_here");
        Assert.Equal("file_name_here", Assert.IsType<MdText>(Assert.Single(snake)).Text);

        var url = Inlines("https://host/a_b_c");
        Assert.Equal("https://host/a_b_c", PlainText(url));
        Assert.DoesNotContain(url, i => i is MdItalic);
    }

    [Fact]
    public void Link_ParsesLabelAndUrl()
    {
        var link = Assert.IsType<MdLink>(Inlines("[x64](https://example/setup.exe)").Single());
        Assert.Equal("x64", PlainText(link.Label));
        Assert.Equal("https://example/setup.exe", link.Url);
    }

    [Fact]
    public void BackslashEscape_PreventsFormatting()
    {
        var result = Inlines(@"literal \*stars\* here");
        Assert.Equal("literal *stars* here", PlainText(result));
        Assert.DoesNotContain(result, i => i is MdItalic);
    }

    [Fact]
    public void HtmlEntities_AreDecoded()
    {
        Assert.Equal("a · b", PlainText(Inlines("a &middot; b")));
        Assert.Equal("Tom & Jerry", PlainText(Inlines("Tom &amp; Jerry")));
        Assert.Equal("<tag>", PlainText(Inlines("&lt;tag&gt;")));
    }

    [Fact]
    public void UnterminatedDelimiters_StayLiteral()
    {
        Assert.Equal("a * b", PlainText(Inlines("a * b")));
        Assert.Equal("[not a link", PlainText(Inlines("[not a link")));
        Assert.Equal("`unclosed", PlainText(Inlines("`unclosed")));
    }

    [Fact]
    public void Headings_CaptureLevelAndText()
    {
        var h2 = Assert.IsType<MdHeading>(MarkdownParser.Parse("## Downloads").Single());
        Assert.Equal(2, h2.Level);
        Assert.Equal("Downloads", PlainText(h2.Inlines));

        var h3 = Assert.IsType<MdHeading>(MarkdownParser.Parse("### VirusTotal scans").Single());
        Assert.Equal(3, h3.Level);
    }

    [Fact]
    public void UnorderedList_GroupsConsecutiveItems()
    {
        var list = Assert.IsType<MdList>(MarkdownParser.Parse("- one\n- two\n- three").Single());
        Assert.Equal(3, list.Items.Count);
        Assert.All(list.Items, it => Assert.Null(it.Ordered));
        Assert.Equal("one", PlainText(list.Items[0].Inlines));
        Assert.Equal("three", PlainText(list.Items[2].Inlines));
    }

    [Fact]
    public void OrderedList_CapturesNumbers()
    {
        var list = Assert.IsType<MdList>(MarkdownParser.Parse("1. first\n2. second").Single());
        Assert.Equal(1, list.Items[0].Ordered);
        Assert.Equal(2, list.Items[1].Ordered);
    }

    [Fact]
    public void NestedList_HasDeeperLevel()
    {
        var list = Assert.IsType<MdList>(MarkdownParser.Parse("- top\n  - nested").Single());
        Assert.Equal(0, list.Items[0].Level);
        Assert.Equal(1, list.Items[1].Level);
    }

    [Fact]
    public void FencedCodeBlock_IsCapturedVerbatim()
    {
        var code = Assert.IsType<MdCode>(MarkdownParser.Parse("```\nline 1\nline 2\n```").Single());
        Assert.Equal("line 1\nline 2", code.Text);
    }

    [Fact]
    public void HorizontalRule_IsRecognized()
    {
        Assert.IsType<MdRule>(MarkdownParser.Parse("---").Single());
        Assert.IsType<MdRule>(MarkdownParser.Parse("***").Single());
    }

    [Fact]
    public void Paragraph_JoinsSoftWrappedLines()
    {
        var para = Assert.IsType<MdParagraph>(MarkdownParser.Parse("one\ntwo").Single());
        Assert.Equal("one two", PlainText(para.Inlines));
    }

    [Fact]
    public void RealReleaseNotes_ParseIntoExpectedBlockShape()
    {
        // Mirrors the CI-generated body: a Downloads heading + bold/link bullets, then a Changes section.
        const string notes =
            "## Downloads\n\n" +
            "- **Installer:** Windows [x64](https://example/setup-x64.exe) / [ARM](https://example/setup-arm.exe)\n" +
            "- **Linux:** Deb [x64](https://example/app.deb) &middot; RPM [x64](https://example/app.rpm)\n\n" +
            "## Changes since v1.2.0\n\n" +
            "- Add folders to organize accounts (`abc1234`)\n" +
            "- Fix update popup crash (`def5678`)\n";

        var blocks = MarkdownParser.Parse(notes);
        Assert.Collection(blocks,
            b => Assert.Equal("Downloads", PlainText(Assert.IsType<MdHeading>(b).Inlines)),
            b => Assert.Equal(2, Assert.IsType<MdList>(b).Items.Count),
            b => Assert.Equal("Changes since v1.2.0", PlainText(Assert.IsType<MdHeading>(b).Inlines)),
            b => Assert.Equal(2, Assert.IsType<MdList>(b).Items.Count));

        // The first bullet keeps its bold lead-in, both links, and the literal slash between them.
        var firstBullet = ((MdList)blocks[1]).Items[0];
        Assert.Equal("Installer: Windows x64 / ARM", PlainText(firstBullet.Inlines));
        Assert.Equal(2, firstBullet.Inlines.Count(i => i is MdLink));
        // The &middot; entity in the second bullet is decoded.
        Assert.Contains("·", PlainText(((MdList)blocks[1]).Items[1].Inlines));
    }
}

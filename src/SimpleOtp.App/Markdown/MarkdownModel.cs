using System.Collections.Generic;

namespace SimpleOtp.App.Markdown;

// A tiny, dependency-free model of the markdown subset that appears in GitHub release notes
// (headings, bullet/numbered lists, paragraphs, fenced code, rules; bold/italic/code/link inlines).
// Kept separate from the Avalonia rendering so the parser can be unit-tested without a UI.

internal abstract record MdBlock;

/// <summary>A heading, <c>#</c>..<c>######</c> (<see cref="Level"/> 1-6).</summary>
internal sealed record MdHeading(int Level, IReadOnlyList<MdInline> Inlines) : MdBlock;

internal sealed record MdParagraph(IReadOnlyList<MdInline> Inlines) : MdBlock;

/// <summary>A run of consecutive list items (ordered or unordered).</summary>
internal sealed record MdList(IReadOnlyList<MdListItem> Items) : MdBlock;

/// <summary>
/// One list item. <see cref="Ordered"/> is the number for "1." style items, or null for bullets.
/// <see cref="Level"/> is the nesting depth (0 = top level), derived from leading indentation.
/// </summary>
internal sealed record MdListItem(int Level, int? Ordered, IReadOnlyList<MdInline> Inlines);

/// <summary>A fenced code block (``` ... ```). Rendered verbatim, monospaced.</summary>
internal sealed record MdCode(string Text) : MdBlock;

/// <summary>A horizontal rule (---, ***, ___).</summary>
internal sealed record MdRule : MdBlock;

internal abstract record MdInline;

internal sealed record MdText(string Text) : MdInline;
internal sealed record MdBold(IReadOnlyList<MdInline> Inlines) : MdInline;
internal sealed record MdItalic(IReadOnlyList<MdInline> Inlines) : MdInline;
internal sealed record MdCodeSpan(string Text) : MdInline;
internal sealed record MdLink(IReadOnlyList<MdInline> Label, string Url) : MdInline;

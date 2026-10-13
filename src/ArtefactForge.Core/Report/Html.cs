using System.Globalization;
using System.Net;

namespace ArtefactForge.Core.Report;

/// <summary>Small helpers for building the report's HTML. Every value from the case goes through <see cref="E"/>.</summary>
internal static class Html
{
    /// <summary>Escapes text for an element body or a quoted attribute.</summary>
    public static string E(string? text) => WebUtility.HtmlEncode(text ?? "");

    public static string Pill(string text, string kind) => $"<span class=\"pill p-{kind}\">{E(text)}</span>";

    public static string Muted(string text) => $"<span class=\"muted\">{E(text)}</span>";

    /// <summary>A section's placeholder when it has no data, saying why and what to do.</summary>
    public static string Empty(string text) => $"<div class=\"box empty\">{E(text)}</div>";

    /// <summary>yyyy-MM-dd HH:mm:ss, the form every summary file uses.</summary>
    public static string Time(DateTime? time) =>
        time?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "";

    public static string Day(DateTime? time) =>
        time?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";

    public static string N(long n) => n.ToString("N0", CultureInfo.InvariantCulture);

    public static string Plural(long n, string one, string many) => n == 1 ? one : many;

    /// <summary>
    /// The line with the first occurrence of <paramref name="value"/> marked, cut to a window
    /// around it when long (an event payload can run to thousands of characters).
    /// </summary>
    public static string Mark(string line, string value, int window = 400)
    {
        var at = value.Length == 0 ? -1 : line.IndexOf(value, StringComparison.OrdinalIgnoreCase);
        if (at < 0 && Path.HasExtension(value))
        {
            value = Path.GetFileNameWithoutExtension(value);
            at = value.Length == 0 ? -1 : line.IndexOf(value, StringComparison.OrdinalIgnoreCase);
        }

        var start = 0;
        var end = line.Length;
        if (line.Length > window)
        {
            start = at < 0 ? 0 : Math.Max(0, at - window / 2);
            end = Math.Min(line.Length, start + window);
        }

        string Cut(int from, int to) => from >= to ? "" : E(line[from..to]);
        var prefix = start > 0 ? "..." : "";
        var suffix = end < line.Length ? "..." : "";
        if (at < 0 || at + value.Length > end) return prefix + Cut(start, end) + suffix;
        return prefix + Cut(start, at) + "<mark>" + E(line.Substring(at, value.Length)) + "</mark>"
               + Cut(at + value.Length, end) + suffix;
    }
}

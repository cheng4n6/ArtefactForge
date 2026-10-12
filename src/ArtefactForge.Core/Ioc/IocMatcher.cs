using System.Buffers;

namespace ArtefactForge.Core.Ioc;

/// <summary>What the header of one output CSV says about where to look.</summary>
public sealed class CsvHeader
{
    public required string[] Names { get; init; }
    /// <summary>Columns whose name says they hold a hash (SHA1, MD5, Hashes ...).</summary>
    public required int[] HashColumns { get; init; }
    /// <summary>Columns whose name says they hold a time or date, in header order.</summary>
    public required int[] TimeColumns { get; init; }

    public static CsvHeader Parse(string headerRecord)
    {
        var names = CsvText.Split(headerRecord).Select(n => n.Trim().TrimStart('\uFEFF')).ToArray();
        return new CsvHeader
        {
            Names = names,
            HashColumns = Enumerable.Range(0, names.Length).Where(i => IsHashColumn(names[i])).ToArray(),
            TimeColumns = Enumerable.Range(0, names.Length).Where(i => IsTimeColumn(names[i])).ToArray()
        };
    }

    public static bool IsHashColumn(string name)
    {
        var n = name.ToLowerInvariant();
        if (n.Contains("hash") || n.Contains("md5") || n == "sha") return true;
        // SHA1, SHA-256, sha512sum ... but not Shadow or Shared.
        var at = n.IndexOf("sha", StringComparison.Ordinal);
        return at >= 0 && at + 3 < n.Length && (char.IsDigit(n[at + 3]) || n[at + 3] == '-');
    }

    public static bool IsTimeColumn(string name)
    {
        var n = name.ToLowerInvariant();
        return (n.Contains("time") || n.Contains("date")) && !n.Contains("zone");
    }

    /// <summary>The first non-empty time in the row, for the Time column of a hit.</summary>
    public string TimeOf(string[] fields)
    {
        foreach (var index in TimeColumns)
            if (index < fields.Length && fields[index].Trim().Length > 0) return fields[index].Trim();
        return "";
    }
}

/// <summary>
/// Finds IOCs in the records of an output CSV.
///
/// - File names match on the whole name in any folder, ignoring case: ABC.exe matches
///   C:\Temp\ABC.exe and "abc.exe", not XABC.exe or ABC.exe.bak.
/// - Paths match the whole path, with either separator, with doubled backslashes (JSON in event
///   payloads), and without the drive letter (\Device\HarddiskVolume3\Users\...).
/// - Hashes match in any column whose header names a hash, as a whole value or as one of
///   several (Sysmon's "SHA1=...,MD5=..."), and Amcache's FileId (0000 followed by the SHA1).
/// - IPs, domains and accounts match anywhere in a line as a whole value: 10.0.0.1 does not
///   match 10.0.0.12, alice does not match malice. A domain matches its subdomains too.
///
/// Every record is first checked for any IOC value in one pass (SearchValues), so the large
/// majority of lines in a multi-GB file cost a single scan, however long the list.
/// </summary>
public sealed class IocMatcher
{
    private sealed record Needle(IocEntry Entry, IocType Type, string[] Variants);

    private readonly List<Needle> _needles;
    private readonly SearchValues<string>? _any;

    public IocMatcher(IEnumerable<IocEntry> iocs)
    {
        _needles = iocs.Where(i => i.IsSweepable)
                       .Select(i => new Needle(i, i.Type!.Value, Variants(i.Type!.Value, i.Value.Trim())))
                       .ToList();
        var all = _needles.SelectMany(n => n.Variants).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _any = all.Length == 0 ? null : SearchValues.Create(all, StringComparison.OrdinalIgnoreCase);
    }

    public bool IsEmpty => _needles.Count == 0;

    public IReadOnlyList<IocEntry> Iocs => _needles.Select(n => n.Entry).ToList();

    /// <summary>The IOCs found in one record. Fields are split only when a record is a candidate.</summary>
    public List<IocEntry> Match(string record, CsvHeader header, out string[]? fields)
    {
        fields = null;
        var found = new List<IocEntry>();
        if (_any is null || record.AsSpan().IndexOfAny(_any) < 0) return found;

        foreach (var needle in _needles)
        {
            if (needle.Type == IocType.Hash)
            {
                if (header.HashColumns.Length == 0) continue;
                fields ??= CsvText.Split(record);
                if (HashInFields(fields, header.HashColumns, needle.Variants[0])) found.Add(needle.Entry);
                continue;
            }

            foreach (var variant in needle.Variants)
            {
                if (!Bounded(record, variant, needle.Type)) continue;
                found.Add(needle.Entry);
                break;
            }
        }
        return found;
    }

    private static string[] Variants(IocType type, string value)
    {
        switch (type)
        {
            case IocType.Path:
            {
                var back = value.Replace('/', '\\');
                var forms = new List<string> { back };
                // Event payloads and some tools write the path without its drive letter.
                if (back.Length > 2 && back[1] == ':' && back[2] == '\\') forms.Add(back[2..]);
                return forms.SelectMany(f => new[] { f, f.Replace('\\', '/'), f.Replace("\\", "\\\\") })
                            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            }
            case IocType.Account when value.Contains('\\'):
                return [value, value.Replace("\\", "\\\\")];
            default:
                return [value];
        }
    }

    private static bool HashInFields(string[] fields, int[] columns, string hash)
    {
        foreach (var index in columns)
        {
            if (index >= fields.Length) continue;
            var field = fields[index].Trim();
            if (field.Length < hash.Length) continue;
            // Amcache writes FileId as 0000 followed by the SHA1.
            if (field.Length == hash.Length + 4 && field.StartsWith("0000", StringComparison.Ordinal)
                && field.EndsWith(hash, StringComparison.OrdinalIgnoreCase)) return true;
            if (Bounded(field, hash, IocType.Hash)) return true;
        }
        return false;
    }

    /// <summary>True when <paramref name="value"/> occurs in <paramref name="text"/> as a whole value for its type.</summary>
    public static bool Bounded(string text, string value, IocType type)
    {
        if (value.Length == 0) return false;
        var from = 0;
        while (from <= text.Length - value.Length)
        {
            var at = text.IndexOf(value, from, StringComparison.OrdinalIgnoreCase);
            if (at < 0) return false;
            var end = at + value.Length;
            if (StartsClean(text, at, value, type) && EndsClean(text, end, value, type)) return true;
            from = at + 1;
        }
        return false;
    }

    private static bool StartsClean(string text, int at, string value, IocType type)
    {
        if (at == 0) return true;
        var before = text[at - 1];
        return type switch
        {
            // A path begins with its drive or a separator; what comes before it does not matter.
            IocType.Path => true,
            IocType.IP => !IsIpChar(before, value),
            IocType.Hash => !char.IsAsciiHexDigit(before),
            // A dot before is a subdomain, which counts.
            IocType.Domain => !(char.IsAsciiLetterOrDigit(before) || before == '-'),
            _ => !IsNameChar(before)
        };
    }

    private static bool EndsClean(string text, int end, string value, IocType type)
    {
        if (end >= text.Length) return true;
        var after = text[end];
        return type switch
        {
            // A folder's path is followed by a separator; a file's by the end of the name.
            IocType.Path => !IsNameChar(after) || value.EndsWith('\\') || value.EndsWith('/'),
            IocType.IP => !IsIpChar(after, value),
            IocType.Hash => !char.IsAsciiHexDigit(after),
            // evil.com is not evil.com.au or evil.community; a full stop ending a sentence is fine.
            IocType.Domain => !(char.IsAsciiLetterOrDigit(after) || after == '-')
                              && !(after == '.' && end + 1 < text.Length && char.IsAsciiLetterOrDigit(text[end + 1])),
            _ => !IsNameChar(after)
        };
    }

    // Characters that continue a file or account name, so a match next to one is part of a longer name.
    private static bool IsNameChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or '$';

    private static bool IsIpChar(char c, string ip) =>
        ip.Contains(':') ? char.IsAsciiHexDigit(c) || c is ':' or '.' : char.IsAsciiDigit(c) || c == '.';
}

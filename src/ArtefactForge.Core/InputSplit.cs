using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace ArtefactForge.Core;

/// <summary>
/// Shares a Split step's input files out into parts of about the same size, links them into a
/// folder per part, and joins the parts' CSVs back into one. The evidence is never copied or
/// touched: each part's folder holds hard links, which need the same NTFS volume as the evidence.
/// </summary>
public static class InputSplit
{
    /// <summary>
    /// Parts for "auto". Four took EvtxECmd from 159 s to 54 s over 265 logs on a 16-core PC;
    /// each part loads EvtxECmd's maps again, so many more buys little.
    /// </summary>
    public const int AutoParts = 4;

    /// <summary>Below this much input, "auto" runs one process: starting more costs more than it saves.</summary>
    public const long AutoMinimumBytes = 50L << 20;

    /// <summary>"auto" (null) or a whole number of parts from 1 to 64.</summary>
    public static bool TryParseParts(string value, out int? parts)
    {
        parts = null;
        if (value.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase)) return true;
        if (int.TryParse(value.Trim(), out var n) && n is >= 1 and <= 64)
        {
            parts = n;
            return true;
        }
        return false;
    }

    /// <summary>How many parts to run, never more than there are files.</summary>
    public static int Parts(string? setting, int files, long bytes)
    {
        int? asked = null;
        if (setting is not null && TryParseParts(setting, out var parsed)) asked = parsed;
        var parts = asked ?? (bytes < AutoMinimumBytes ? 1 : AutoParts);
        return Math.Max(1, Math.Min(parts, files));
    }

    /// <summary>
    /// Largest file first into the lightest part, so the parts come out about the same size and
    /// the same files always land in the same part. Each part lists its files by name.
    /// </summary>
    public static List<List<string>> Group(IReadOnlyList<(string Path, long Length)> files, int parts)
    {
        var groups = Enumerable.Range(0, Math.Max(1, parts)).Select(_ => (Files: new List<string>(), Bytes: 0L)).ToList();
        foreach (var file in files.OrderByDescending(f => f.Length)
                                  .ThenBy(f => Path.GetFileName(f.Path), StringComparer.OrdinalIgnoreCase))
        {
            var lightest = 0;
            for (var i = 1; i < groups.Count; i++)
                if (groups[i].Bytes < groups[lightest].Bytes) lightest = i;
            groups[lightest].Files.Add(file.Path);
            groups[lightest] = (groups[lightest].Files, groups[lightest].Bytes + file.Length);
        }
        return groups.Where(g => g.Files.Count > 0)
                     .Select(g => g.Files.OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase).ToList())
                     .ToList();
    }

    /// <summary>
    /// Makes part1, part2 ... under <paramref name="root"/>, each holding hard links to its files.
    /// Returns why not, having removed what it made, when a link cannot be made: evidence on
    /// another volume, a share or a file system without hard links.
    /// </summary>
    public static string? Link(IReadOnlyList<List<string>> groups, string root, out List<string> folders)
    {
        folders = [];
        if (!OperatingSystem.IsWindows()) return "hard links are only made on Windows";

        foreach (var (files, index) in groups.Select((g, i) => (g, i)))
        {
            var folder = Path.Combine(root, "part" + (index + 1));
            Directory.CreateDirectory(folder);
            folders.Add(folder);
            foreach (var file in files)
            {
                if (CreateHardLink(Path.Combine(folder, Path.GetFileName(file)), file, IntPtr.Zero)) continue;

                var error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                // Deleting a hard link leaves the file it points at as it was.
                foreach (var made in folders)
                    try { Directory.Delete(made, recursive: true); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                folders = [];
                return $"could not hard-link {Path.GetFileName(file)} into {root}: {error}";
            }
        }
        return null;
    }

    /// <summary>
    /// Joins the parts' CSVs, in order, into <paramref name="target"/>: the first header once,
    /// then every part's rows. A part that wrote no file is passed over. Returns why not when the
    /// headers differ or a part cannot be read; the caller then keeps the parts as they are.
    ///
    /// Copied as bytes after the header line, so quoted fields that run over several lines (an
    /// EvtxECmd payload) come through untouched. Parts that wrote only empty files give an empty
    /// file, which the engine reports as such.
    ///
    /// <paramref name="folders"/>, when given, holds each part's folder and the folder it stands
    /// for. A tool records the path it read each row from (EvtxECmd's SourceFile), which for a part
    /// is a link in _Staging that is gone after the run; it is written as the evidence path instead,
    /// exactly as an unsplit run gives it.
    /// </summary>
    public static async Task<string?> MergeAsync(
        IReadOnlyList<string> parts, string target, CancellationToken cancellationToken,
        IReadOnlyList<(string Part, string Original)>? folders = null)
    {
        string? header = null;
        string? headerFrom = null;
        var any = false;
        var endsWithNewline = true;

        await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            for (var p = 0; p < parts.Count; p++)
            {
                var part = parts[p];
                if (!File.Exists(part)) continue;
                any = true;
                await using var input = new FileStream(part, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
                var line = ReadHeaderLine(input);
                if (line is null)
                    return $"{Path.GetFileName(part)} has no header line ending within its first 1 MB - not joined";
                if (line.Length == 0) continue;

                var text = Encoding.UTF8.GetString(line).TrimStart('﻿').TrimEnd('\r', '\n');
                if (header is null)
                {
                    header = text;
                    headerFrom = part;
                    await output.WriteAsync(line, cancellationToken);
                    endsWithNewline = line[^1] == '\n';
                }
                else if (!string.Equals(header, text, StringComparison.Ordinal))
                {
                    return $"{Path.GetFileName(part)} has a different header from {Path.GetFileName(headerFrom)} - not joined";
                }

                if (input.Position == input.Length) continue;
                if (!endsWithNewline) await output.WriteAsync("\r\n"u8.ToArray(), cancellationToken);
                if (folders is null) await input.CopyToAsync(output, cancellationToken);
                else await CopyReplacingAsync(input, output, Separated(folders[p].Part), Separated(folders[p].Original), cancellationToken);
                input.Seek(-1, SeekOrigin.End);
                endsWithNewline = input.ReadByte() == '\n';
            }
        }

        if (!any) File.Delete(target);
        return null;
    }

    /// <summary>A folder as it begins a path inside it, in UTF-8: "C:\x\part1\".</summary>
    private static byte[] Separated(string folder) =>
        Encoding.UTF8.GetBytes(folder.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);

    /// <summary>
    /// Copies the rest of <paramref name="input"/>, writing <paramref name="to"/> wherever
    /// <paramref name="from"/> appears, including across the reads it is copied in.
    /// </summary>
    private static async Task CopyReplacingAsync(
        Stream input, Stream output, byte[] from, byte[] to, CancellationToken cancellationToken)
    {
        var buffer = new byte[(1 << 20) + from.Length];
        var filled = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer.AsMemory(filled, buffer.Length - filled), cancellationToken);
            filled += read;
            var end = read == 0;
            // A match may begin in the last few bytes and finish in the next read; they wait for it.
            var safe = end ? filled : Math.Max(0, filled - (from.Length - 1));
            var start = 0;
            while (start < safe)
            {
                var at = buffer.AsSpan(start, filled - start).IndexOf(from);
                if (at < 0 || start + at >= safe) break;
                await output.WriteAsync(buffer.AsMemory(start, at), cancellationToken);
                await output.WriteAsync(to, cancellationToken);
                start += at + from.Length;
            }
            var keep = Math.Max(start, safe);
            await output.WriteAsync(buffer.AsMemory(start, keep - start), cancellationToken);
            if (end) return;
            Buffer.BlockCopy(buffer, keep, buffer, 0, filled - keep);
            filled -= keep;
        }
    }

    /// <summary>
    /// The first line with its line ending (the whole file when it has only that line), empty for
    /// an empty file, or null when no line ends within 1 MB.
    /// </summary>
    private static byte[]? ReadHeaderLine(Stream input)
    {
        var line = new List<byte>();
        while (line.Count < 1 << 20)
        {
            var b = input.ReadByte();
            if (b < 0) return [.. line];
            line.Add((byte)b);
            if (b == '\n') return [.. line];
        }
        return null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);
}

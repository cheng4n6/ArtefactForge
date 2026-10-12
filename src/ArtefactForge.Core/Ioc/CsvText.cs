using System.Text;

namespace ArtefactForge.Core.Ioc;

/// <summary>One CSV record: the line it starts on and its text, which spans lines when a quoted field holds a line break.</summary>
public readonly record struct CsvRecord(long LineNumber, string Text);

/// <summary>
/// Streaming CSV for the IOC sweep. Module output can run to several GB (an MFT or a busy EVTX
/// export), so records are read one at a time and never the whole file.
/// </summary>
public static class CsvText
{
    // A quote left open by a malformed file would otherwise swallow the rest of it into one
    // record. Past this size the record is let go and reading carries on at the next line.
    private const int MaxRecordChars = 1 << 20;

    public static IEnumerable<CsvRecord> Records(TextReader reader)
    {
        long lineNumber = 0;
        StringBuilder? pending = null;
        long pendingStart = 0;
        var open = false;

        while (reader.ReadLine() is { } line)
        {
            lineNumber++;
            var quotes = line.AsSpan().Count('"');

            if (pending is null)
            {
                if (quotes % 2 == 0)
                {
                    yield return new CsvRecord(lineNumber, line);
                    continue;
                }
                pending = new StringBuilder(line);
                pendingStart = lineNumber;
                open = true;
                continue;
            }

            pending.Append('\n').Append(line);
            if (quotes % 2 == 1) open = !open;
            if (!open || pending.Length > MaxRecordChars)
            {
                yield return new CsvRecord(pendingStart, pending.ToString());
                pending = null;
                open = false;
            }
        }

        if (pending is not null) yield return new CsvRecord(pendingStart, pending.ToString());
    }

    /// <summary>RFC 4180 fields: quotes removed, "" read as one quote.</summary>
    public static string[] Split(string record)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var quoted = false;

        for (var i = 0; i < record.Length; i++)
        {
            var c = record[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < record.Length && record[i + 1] == '"') { current.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else current.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(current.ToString()); current.Clear(); }
            else current.Append(c);
        }

        fields.Add(current.ToString());
        return [.. fields];
    }

    public static string Escape(string value) =>
        value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r')
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;

    /// <summary>Opens a file for a sequential read that does not stop another program using it.</summary>
    public static StreamReader OpenRead(string path) =>
        new(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                           1 << 16, FileOptions.SequentialScan),
            Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 16);
}

/// <summary>
/// Writes a file through a temporary file beside it that then replaces the original, so the
/// original is either the old content or the new, never half written.
/// </summary>
public static class AtomicFile
{
    public static void WriteAllText(string path, string content) =>
        Write(path, writer => writer.Write(content));

    /// <summary>
    /// Writes through <paramref name="write"/> into a temporary file, then swaps it in. If anything
    /// fails the original is untouched and the temporary file is removed.
    /// </summary>
    public static void Write(string path, Action<StreamWriter> write)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        var temp = Path.Combine(directory, Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
            {
                write(writer);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            // A rename within one folder: the original is swapped in one step, on a share too.
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(temp);
            throw new IOException(
                $"Could not save {Path.GetFileName(path)} ({ex.Message}). Is it open in another program? "
                + "The file on disk was not changed.", ex);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* a stray .tmp beside the list is untidy, not harmful */ }
    }
}

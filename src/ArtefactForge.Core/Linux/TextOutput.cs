using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// CSV written the way the PowerShell parsers write it - every cell quoted, UTF-8 with a BOM, CRLF -
/// so output from builtin and script modules opens identically in Timeline Explorer and Excel.
/// </summary>
internal sealed class CsvFile : IDisposable
{
    private static readonly UTF8Encoding Utf8Bom = new(encoderShouldEmitUTF8Identifier: true);

    private readonly string _path;
    private readonly string[] _header;
    private StreamWriter? _writer;

    public int Rows { get; private set; }
    public string FileName => Path.GetFileName(_path);

    /// <summary>Nothing is created until the first row, so a file never exists with only a header.</summary>
    public CsvFile(string path, params string[] header)
    {
        _path = path;
        _header = header;
    }

    public void Write(params string[] cells)
    {
        if (_writer is null)
        {
            _writer = new StreamWriter(_path, false, Utf8Bom);
            WriteRow(_writer, _header);
        }
        WriteRow(_writer, cells);
        Rows++;
    }

    public static void WriteRow(TextWriter writer, params string[] cells)
    {
        for (var i = 0; i < cells.Length; i++)
        {
            if (i > 0) writer.Write(',');
            writer.Write('"');
            writer.Write(cells[i].Replace("\"", "\"\""));
            writer.Write('"');
        }
        writer.Write("\r\n");
    }

    public void Dispose() => _writer?.Dispose();
}

/// <summary>Plain-text logs with logrotate history.</summary>
internal static class RotatedLogs
{
    private static readonly Regex NumberSuffix = new(@"\.(\d+)(\.gz)?$", RegexOptions.Compiled);
    private static readonly Regex DateSuffix = new(@"-(\d{8})(\.gz)?$", RegexOptions.Compiled);

    /// <summary>
    /// Oldest first: access.log.10.gz ... access.log.1, access.log. Sorting by name alone puts the
    /// live file first and .10 before .2. Date-suffixed rotations (access_log-20230101) sort by date.
    /// </summary>
    public static IEnumerable<FileInfo> Order(IEnumerable<FileInfo> files) =>
        files.OrderBy(f => BaseName(f.Name), StringComparer.Ordinal)
             .ThenBy(f =>
             {
                 var n = NumberSuffix.Match(f.Name);
                 if (n.Success) return -long.Parse(n.Groups[1].Value);
                 var d = DateSuffix.Match(f.Name);
                 return d.Success ? long.Parse(d.Groups[1].Value) - 100_000_000L : 0L;
             });

    private static string BaseName(string name)
    {
        var n = NumberSuffix.Match(name);
        if (n.Success) return name[..n.Index];
        var d = DateSuffix.Match(name);
        if (d.Success) return name[..d.Index];
        return name.EndsWith(".gz") ? name[..^3] : name;
    }

    /// <summary>
    /// Lines of a log, gunzipping a rotated .gz transparently.
    ///
    /// .NET's GZipStream ends quietly at the end of a truncated file, so a partial copy would read as
    /// a short log. The gzip trailer records the uncompressed length; if the bytes read disagree with
    /// it, the file is reported as truncated after its readable lines have been returned.
    /// </summary>
    public static IEnumerable<string> ReadLines(FileInfo file)
    {
        var gzip = file.Name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase);
        using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var counter = new CountingStream(gzip ? new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true) : stream);
        using (var reader = new StreamReader(counter, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true))
        {
            string? line;
            while ((line = reader.ReadLine()) is not null) yield return line;
        }

        if (!gzip) yield break;
        if (stream.Length < 18) throw new InvalidDataException("gzip file too short to be complete - truncated?");
        var trailer = new byte[4];
        stream.Seek(-4, SeekOrigin.End);
        stream.ReadExactly(trailer);
        if (BitConverter.ToUInt32(trailer) != (uint)counter.BytesRead)
            throw new InvalidDataException("gzip data ends before its recorded length - file truncated?");
    }

    private sealed class CountingStream(Stream inner) : Stream
    {
        public long BytesRead { get; private set; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = inner.Read(buffer, offset, count);
            BytesRead += n;
            return n;
        }
        public override int Read(Span<byte> buffer)
        {
            var n = inner.Read(buffer);
            BytesRead += n;
            return n;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => BytesRead; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }
}

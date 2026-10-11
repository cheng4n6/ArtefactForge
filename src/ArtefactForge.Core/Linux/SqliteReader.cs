using System.Buffers.Binary;
using System.Text;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// A read-only reader for SQLite database files, written for evidence rather than for an
/// application: it never opens the file for writing, never creates a -journal or -shm, and never
/// checkpoints a WAL - the file on disk is exactly as found afterwards.
///
/// A -wal file beside the database is read and its committed frames applied in memory, because
/// that is where the most recent writes sit until a checkpoint moves them into the main file.
/// Frames after the last commit, and any frame whose checksum or salt does not match, are not
/// applied and are counted in <see cref="Notes"/>.
///
/// Covers table b-trees, overflow pages and every record serial type; enough to read any table
/// by name. Not a query engine and not a carver: deleted rows and freelist pages are not read.
/// Format reference: sqlite.org/fileformat2.html.
/// </summary>
public sealed class SqliteReader
{
    private readonly byte[] _file;
    private readonly Dictionary<uint, byte[]> _walPages = [];
    private readonly Encoding _text;

    public int PageSize { get; }
    public int UsableSize { get; }
    public List<string> Notes { get; } = [];

    private SqliteReader(byte[] file, byte[]? wal)
    {
        _file = file;
        if (file.Length < 100 || Encoding.ASCII.GetString(file, 0, 15) != "SQLite format 3")
            throw new InvalidDataException("not an SQLite database (bad header)");

        var pageSize = BinaryPrimitives.ReadUInt16BigEndian(file.AsSpan(16));
        PageSize = pageSize == 1 ? 65536 : pageSize;
        if (PageSize < 512 || (PageSize & (PageSize - 1)) != 0)
            throw new InvalidDataException($"page size {PageSize} is not valid");
        UsableSize = PageSize - file[20];

        _text = BinaryPrimitives.ReadUInt32BigEndian(file.AsSpan(56)) switch
        {
            2 => Encoding.Unicode,
            3 => Encoding.BigEndianUnicode,
            _ => Encoding.UTF8
        };

        if (wal is not null) ApplyWal(wal);
    }

    /// <summary>Opens the database and, if present, its -wal. Both are read once, fully, and shared for reading.</summary>
    public static SqliteReader Open(string path)
    {
        var file = ReadShared(path);
        var walPath = path + "-wal";
        byte[]? wal = File.Exists(walPath) ? ReadShared(walPath) : null;
        return new SqliteReader(file, wal is { Length: > 32 } ? wal : null);
    }

    private static byte[] ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > 1L << 30) throw new InvalidDataException($"{Path.GetFileName(path)} is over 1 GB; not read into memory");
        var buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }

    // ------------------------------------------------------------------ WAL

    private void ApplyWal(byte[] wal)
    {
        var magic = BinaryPrimitives.ReadUInt32BigEndian(wal);
        if (magic is not (0x377f0682 or 0x377f0683)) { Notes.Add("-wal present but not a WAL file; ignored"); return; }
        var bigEndian = magic == 0x377f0683;

        var walPageSize = (int)BinaryPrimitives.ReadUInt32BigEndian(wal.AsSpan(8));
        if (walPageSize != PageSize) { Notes.Add($"-wal page size {walPageSize} differs from the database's {PageSize}; ignored"); return; }

        var salt1 = BinaryPrimitives.ReadUInt32BigEndian(wal.AsSpan(16));
        var salt2 = BinaryPrimitives.ReadUInt32BigEndian(wal.AsSpan(20));
        var (s0, s1) = Checksum(wal.AsSpan(0, 24), 0, 0, bigEndian);
        if (s0 != BinaryPrimitives.ReadUInt32BigEndian(wal.AsSpan(24)) || s1 != BinaryPrimitives.ReadUInt32BigEndian(wal.AsSpan(28)))
        {
            Notes.Add("-wal header checksum does not match; ignored");
            return;
        }

        var frameSize = 24 + PageSize;
        var pending = new Dictionary<uint, byte[]>();
        int frames = 0, committed = 0;
        var total = (wal.Length - 32) / frameSize;
        for (var offset = 32; offset + frameSize <= wal.Length; offset += frameSize)
        {
            var header = wal.AsSpan(offset, 24);
            // A salt mismatch is normal: frames left over from before the last checkpoint reset.
            if (BinaryPrimitives.ReadUInt32BigEndian(header[8..]) != salt1 ||
                BinaryPrimitives.ReadUInt32BigEndian(header[12..]) != salt2) break;

            (s0, s1) = Checksum(header[..8], s0, s1, bigEndian);
            (s0, s1) = Checksum(wal.AsSpan(offset + 24, PageSize), s0, s1, bigEndian);
            if (s0 != BinaryPrimitives.ReadUInt32BigEndian(header[16..]) ||
                s1 != BinaryPrimitives.ReadUInt32BigEndian(header[20..]))
            {
                // Damage, not history: everything from here on is unverifiable and is not applied.
                Notes.Add($"-wal: checksum fails at frame {frames + 1} of {total}; it and every later frame not applied");
                break;
            }

            frames++;
            var page = BinaryPrimitives.ReadUInt32BigEndian(header);
            pending[page] = wal.AsSpan(offset + 24, PageSize).ToArray();

            // A non-zero database size marks the last frame of a committed transaction.
            if (BinaryPrimitives.ReadUInt32BigEndian(header[4..]) != 0)
            {
                foreach (var (p, data) in pending) _walPages[p] = data;
                committed = frames;
                pending.Clear();
            }
        }

        if (committed > 0) Notes.Add($"-wal: {committed} committed frame(s) applied");
        if (frames > committed) Notes.Add($"-wal: {frames - committed} frame(s) after the last commit not applied (an unfinished transaction)");
    }

    private static (uint, uint) Checksum(ReadOnlySpan<byte> data, uint s0, uint s1, bool bigEndian)
    {
        for (var i = 0; i + 8 <= data.Length; i += 8)
        {
            var x0 = bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(data[i..]) : BinaryPrimitives.ReadUInt32LittleEndian(data[i..]);
            var x1 = bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(data[(i + 4)..]) : BinaryPrimitives.ReadUInt32LittleEndian(data[(i + 4)..]);
            s0 += x0 + s1;
            s1 += x1 + s0;
        }
        return (s0, s1);
    }

    // ---------------------------------------------------------------- pages

    private ReadOnlySpan<byte> Page(uint number)
    {
        if (number == 0) throw new InvalidDataException("reference to page 0");
        if (_walPages.TryGetValue(number, out var fromWal)) return fromWal;
        var offset = (long)(number - 1) * PageSize;
        if (offset + PageSize > _file.Length) throw new InvalidDataException($"page {number} is beyond the end of the file");
        return _file.AsSpan((int)offset, PageSize);
    }

    // ---------------------------------------------------------------- schema

    public sealed record TableInfo(string Name, uint RootPage, IReadOnlyList<string> Columns, IReadOnlyList<object?> Defaults, int RowIdAlias);

    public IReadOnlyList<TableInfo> Tables()
    {
        var tables = new List<TableInfo>();
        foreach (var (_, row) in ReadTree(1))
        {
            if (row.Length < 5 || row[0] as string != "table" || row[1] is not string name || row[3] is not long root || root <= 0) continue;
            var (columns, defaults, alias) = ParseColumns(row[4] as string ?? "");
            tables.Add(new TableInfo(name, (uint)root, columns, defaults, alias));
        }
        return tables;
    }

    public TableInfo? Table(string name) =>
        Tables().FirstOrDefault(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Rows as column name to value: long, double, string, byte[] or null. A column declared
    /// INTEGER PRIMARY KEY is an alias for the rowid and is stored as NULL in the record, so it is
    /// filled from the rowid. A row written before ALTER TABLE ADD COLUMN has no value for the new
    /// column in its record, and takes the column's DEFAULT - which is what SQLite itself returns.
    /// </summary>
    public IEnumerable<Dictionary<string, object?>> Rows(string table)
    {
        var info = Table(table) ?? throw new InvalidDataException($"no table '{table}'");
        foreach (var (rowid, values) in ReadTree(info.RootPage))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["_rowid_"] = rowid };
            for (var i = 0; i < info.Columns.Count; i++)
                row[info.Columns[i]] = i == info.RowIdAlias ? rowid : i < values.Length ? values[i] : info.Defaults[i];
            yield return row;
        }
    }

    /// <summary>Column names and literal defaults from a CREATE TABLE statement, and the index of an INTEGER PRIMARY KEY column (or -1).</summary>
    public static (List<string> Columns, List<object?> Defaults, int RowIdAlias) ParseColumns(string sql)
    {
        // Strip comments, then take the text between the outermost parentheses.
        sql = System.Text.RegularExpressions.Regex.Replace(sql, @"/\*.*?\*/|--[^\n]*", " ", System.Text.RegularExpressions.RegexOptions.Singleline);
        var open = sql.IndexOf('(');
        var close = sql.LastIndexOf(')');
        var columns = new List<string>();
        var defaults = new List<object?>();
        var alias = -1;
        if (open < 0 || close <= open) return (columns, defaults, alias);

        var body = sql[(open + 1)..close];
        var depth = 0;
        var start = 0;
        var parts = new List<string>();
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (c is '(') depth++;
            else if (c is ')') depth--;
            else if (c is '\'' or '"' or '`' or '[')
            {
                var end = c == '[' ? ']' : c;
                i = body.IndexOf(end, i + 1);
                if (i < 0) break;
            }
            else if (c == ',' && depth == 0) { parts.Add(body[start..i]); start = i + 1; }
        }
        parts.Add(body[start..]);

        foreach (var raw in parts)
        {
            var part = raw.Trim();
            if (part.Length == 0) continue;
            var first = part.Split((char[])[' ', '\t', '\r', '\n', '('], 2)[0].ToUpperInvariant();
            if (first is "CONSTRAINT" or "PRIMARY" or "FOREIGN" or "UNIQUE" or "CHECK") continue;

            var name = part[0] is '"' or '`' or '[' or '\''
                ? part[1..part.IndexOf(part[0] == '[' ? ']' : part[0], 1)]
                : part.Split((char[])[' ', '\t', '\r', '\n'], 2)[0];
            if (System.Text.RegularExpressions.Regex.IsMatch(part, @"^\S+\s+INTEGER\s+PRIMARY\s+KEY(?!\s+DESC)", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                alias = columns.Count;
            columns.Add(name);
            defaults.Add(ParseDefault(part));
        }
        return (columns, defaults, alias);
    }

    private static readonly System.Text.RegularExpressions.Regex DefaultClause = new(
        @"\bDEFAULT\s+(?:'(?<s>(?:[^']|'')*)'|(?<n>[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)|\((?<p>[-+]?\d+(?:\.\d+)?)\))",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>A literal DEFAULT: string or number. Anything else (NULL, CURRENT_TIMESTAMP, an expression) is null.</summary>
    private static object? ParseDefault(string column)
    {
        var m = DefaultClause.Match(column);
        if (!m.Success) return null;
        if (m.Groups["s"].Success) return m.Groups["s"].Value.Replace("''", "'");
        var number = m.Groups["n"].Success ? m.Groups["n"].Value : m.Groups["p"].Value;
        return long.TryParse(number, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out var l)
            ? (object)l
            : double.Parse(number, System.Globalization.CultureInfo.InvariantCulture);
    }

    // ---------------------------------------------------------------- b-tree

    /// <summary>Every row of a table b-tree, in rowid order.</summary>
    private IEnumerable<(long RowId, object?[] Values)> ReadTree(uint root)
    {
        var visited = new HashSet<uint>();
        var stack = new Stack<uint>();
        stack.Push(root);
        var rows = new List<(long, object?[])>();

        // Depth-first, children pushed in reverse so rows come out in key order. Each page is
        // decoded in a separate method because a span cannot be held across a yield.
        while (stack.Count > 0)
        {
            var number = stack.Pop();
            if (!visited.Add(number)) throw new InvalidDataException($"b-tree loop at page {number}");
            ReadPage(number, stack, rows);
            foreach (var row in rows) yield return row;
            rows.Clear();
        }
    }

    private void ReadPage(uint number, Stack<uint> stack, List<(long, object?[])> rows)
    {
        var page = Page(number);
        var h = number == 1 ? 100 : 0;
        var type = page[h];
        var cells = BinaryPrimitives.ReadUInt16BigEndian(page[(h + 3)..]);

        if (type == 0x05)
        {
            var children = new List<uint>(cells + 1);
            for (var i = 0; i < cells; i++)
            {
                var cell = BinaryPrimitives.ReadUInt16BigEndian(page[(h + 12 + i * 2)..]);
                children.Add(BinaryPrimitives.ReadUInt32BigEndian(page[cell..]));
            }
            children.Add(BinaryPrimitives.ReadUInt32BigEndian(page[(h + 8)..]));
            for (var i = children.Count - 1; i >= 0; i--) stack.Push(children[i]);
        }
        else if (type == 0x0D)
        {
            for (var i = 0; i < cells; i++)
            {
                int cell = BinaryPrimitives.ReadUInt16BigEndian(page[(h + 8 + i * 2)..]);
                var payloadSize = ReadVarint(page, ref cell);
                var rowid = ReadVarint(page, ref cell);
                rows.Add((rowid, DecodeRecord(Payload(page, cell, payloadSize))));
            }
        }
        else
        {
            throw new InvalidDataException($"page {number} is not a table b-tree page (type 0x{type:x2})");
        }
    }

    /// <summary>A cell's payload, following overflow pages when it does not fit on the page.</summary>
    private byte[] Payload(ReadOnlySpan<byte> page, int offset, long size)
    {
        if (size < 0 || size > int.MaxValue) throw new InvalidDataException($"payload size {size} is not plausible");
        var u = UsableSize;
        var maxLocal = u - 35;
        var minLocal = (u - 12) * 32 / 255 - 23;
        int local;
        if (size <= maxLocal) local = (int)size;
        else
        {
            var k = minLocal + (int)((size - minLocal) % (u - 4));
            local = k <= maxLocal ? k : minLocal;
        }

        var payload = new byte[size];
        page.Slice(offset, local).CopyTo(payload);
        if (local == size) return payload;

        var next = BinaryPrimitives.ReadUInt32BigEndian(page[(offset + local)..]);
        var written = local;
        var seen = new HashSet<uint>();
        while (written < size)
        {
            if (next == 0 || !seen.Add(next)) throw new InvalidDataException("overflow chain broken");
            var overflow = Page(next);
            var take = (int)Math.Min(u - 4, size - written);
            overflow.Slice(4, take).CopyTo(payload.AsSpan(written));
            written += take;
            next = BinaryPrimitives.ReadUInt32BigEndian(overflow);
        }
        return payload;
    }

    private object?[] DecodeRecord(byte[] payload)
    {
        var p = 0;
        var headerSize = (int)ReadVarint(payload, ref p);
        var types = new List<long>();
        while (p < headerSize) types.Add(ReadVarint(payload, ref p));

        var values = new object?[types.Count];
        var d = headerSize;
        for (var i = 0; i < types.Count; i++)
        {
            var t = types[i];
            switch (t)
            {
                case 0: values[i] = null; break;
                case 1: values[i] = (long)(sbyte)payload[d]; d += 1; break;
                case 2: values[i] = (long)BinaryPrimitives.ReadInt16BigEndian(payload.AsSpan(d)); d += 2; break;
                case 3: values[i] = (long)((payload[d] << 16 | payload[d + 1] << 8 | payload[d + 2]) << 8 >> 8); d += 3; break;
                case 4: values[i] = (long)BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(d)); d += 4; break;
                case 5:
                    {
                        long v = 0;
                        for (var j = 0; j < 6; j++) v = v << 8 | payload[d + j];
                        values[i] = v << 16 >> 16; d += 6; break;
                    }
                case 6: values[i] = BinaryPrimitives.ReadInt64BigEndian(payload.AsSpan(d)); d += 8; break;
                case 7: values[i] = BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64BigEndian(payload.AsSpan(d))); d += 8; break;
                case 8: values[i] = 0L; break;
                case 9: values[i] = 1L; break;
                case 10 or 11: throw new InvalidDataException($"reserved serial type {t}");
                default:
                    {
                        var length = (int)((t - (t % 2 == 0 ? 12 : 13)) / 2);
                        values[i] = t % 2 == 0 ? payload.AsSpan(d, length).ToArray() : _text.GetString(payload, d, length);
                        d += length;
                        break;
                    }
            }
        }
        return values;
    }

    /// <summary>SQLite's big-endian varint: up to nine bytes, the ninth contributing all eight bits.</summary>
    private static long ReadVarint(ReadOnlySpan<byte> data, ref int offset)
    {
        long value = 0;
        for (var i = 0; i < 8; i++)
        {
            var b = data[offset++];
            value = value << 7 | (long)(b & 0x7F);
            if ((b & 0x80) == 0) return value;
        }
        return value << 8 | data[offset++];
    }

    private static long ReadVarint(byte[] data, ref int offset) => ReadVarint(data.AsSpan(), ref offset);
}

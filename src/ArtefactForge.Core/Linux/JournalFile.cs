using System.IO.MemoryMappedFiles;
using ZstdSharp;

namespace ArtefactForge.Core.Linux;

/// <summary>One journal entry: its header fields and every FIELD=value pair, in file order.</summary>
public sealed class JournalEntry
{
    public required ulong Seqnum { get; init; }
    public required ulong RealtimeUsec { get; init; }
    public required ulong MonotonicUsec { get; init; }
    public required string BootId { get; init; }
    public required IReadOnlyList<KeyValuePair<string, byte[]>> Fields { get; init; }
    public required string SourceFile { get; init; }

    private static readonly ulong MaxUsec = (ulong)(DateTime.MaxValue - DateTime.UnixEpoch).Ticks / 10;

    /// <summary>Wall-clock time the entry was written, UTC. journald records it in microseconds.</summary>
    public DateTime RealtimeUtc => RealtimeUsec >= MaxUsec
        ? DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc)
        : DateTime.UnixEpoch.AddTicks((long)RealtimeUsec * 10);

    /// <summary>First value of a field, or null.</summary>
    public byte[]? Get(string name)
    {
        foreach (var field in Fields)
            if (field.Key == name) return field.Value;
        return null;
    }
}

/// <summary>
/// Reads a systemd journal file (.journal or .journal~) without systemd.
///
/// Entries are found by walking every object in the file from the end of the header, not by
/// following the entry arrays that journalctl uses. The two give the same entries for a cleanly
/// closed file. For a file that was never closed - a .journal~, or one exported from a running
/// system - the walk also recovers entries written after the arrays were last linked, which is
/// where the most recent activity sits. Anything that looks half-written is reported, not guessed at.
///
/// Format reference: systemd's docs/JOURNAL_FILE_FORMAT.md. Covers the regular and compact
/// layouts, and zstd and LZ4 compression. XZ-compressed fields, which only very old systemd wrote,
/// are reported as undecodable rather than skipped silently.
/// </summary>
public sealed class JournalFile : IDisposable
{
    private const string Signature = "LPKSHHRH";
    private const int ObjectHeaderSize = 16;

    private const byte ObjectData = 1;
    private const byte ObjectEntry = 3;

    private const byte ObjectCompressedXz = 1;
    private const byte ObjectCompressedLz4 = 2;
    private const byte ObjectCompressedZstd = 4;

    [Flags]
    public enum IncompatibleFlags : uint
    {
        None = 0,
        CompressedXz = 1,
        CompressedLz4 = 2,
        KeyedHash = 4,
        CompressedZstd = 8,
        Compact = 16
    }

    private const IncompatibleFlags Understood =
        IncompatibleFlags.CompressedXz | IncompatibleFlags.CompressedLz4 | IncompatibleFlags.KeyedHash |
        IncompatibleFlags.CompressedZstd | IncompatibleFlags.Compact;

    private readonly MemoryMappedFile _map;
    private readonly MemoryMappedViewAccessor _view;
    private readonly long _length;
    private readonly Dictionary<ulong, KeyValuePair<string, byte[]>> _dataCache = new();
    private Decompressor? _zstd;

    public string Path { get; }
    public string Name { get; }
    public IncompatibleFlags Flags { get; }
    public bool Compact => (Flags & IncompatibleFlags.Compact) != 0;
    /// <summary>0 offline (closed cleanly), 1 online (open when copied), 2 archived.</summary>
    public byte State { get; }
    public ulong HeaderSize { get; }
    public ulong ArenaSize { get; }
    public ulong HeaderEntryCount { get; }

    /// <summary>Problems met while reading. Each one means some content was not recovered.</summary>
    public List<string> Warnings { get; } = [];

    /// <summary>Fields whose compression this reader does not implement (XZ).</summary>
    public int UndecodedFields { get; private set; }

    private JournalFile(string path, MemoryMappedFile map, MemoryMappedViewAccessor view, long length)
    {
        Path = path;
        Name = System.IO.Path.GetFileName(path);
        _map = map;
        _view = view;
        _length = length;

        var signature = new byte[8];
        _view.ReadArray(0, signature, 0, 8);
        if (System.Text.Encoding.ASCII.GetString(signature) != Signature)
            throw new InvalidDataException("not a journal file (bad signature)");

        Flags = (IncompatibleFlags)_view.ReadUInt32(12);
        State = _view.ReadByte(16);
        HeaderSize = _view.ReadUInt64(88);
        ArenaSize = _view.ReadUInt64(96);
        HeaderEntryCount = _view.ReadUInt64(152);

        var unknown = Flags & ~Understood;
        if (unknown != 0)
            throw new InvalidDataException($"uses format features this reader does not know (0x{(uint)unknown:x}); newer systemd?");
        if (HeaderSize < 208 || HeaderSize > (ulong)_length)
            throw new InvalidDataException($"header size {HeaderSize} is not plausible");
    }

    public static JournalFile Open(string path)
    {
        var info = new FileInfo(path);
        if (info.Length < 208) throw new InvalidDataException($"too short to be a journal ({info.Length} bytes)");

        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        MemoryMappedFile? map = null;
        try
        {
            map = MemoryMappedFile.CreateFromFile(stream, null, 0, MemoryMappedFileAccess.Read,
                HandleInheritability.None, leaveOpen: false);
            var view = map.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            try { return new JournalFile(path, map, view, info.Length); }
            catch { view.Dispose(); throw; }
        }
        catch
        {
            if (map is null) stream.Dispose();
            map?.Dispose();
            throw;
        }
    }

    /// <summary>Every entry in the file, in the order written.</summary>
    public IEnumerable<JournalEntry> ReadEntries(CancellationToken cancellationToken = default)
    {
        var end = (ulong)_length;
        var arenaEnd = HeaderSize + ArenaSize;
        if (arenaEnd < end) end = arenaEnd;

        var offset = HeaderSize;
        while (offset + ObjectHeaderSize <= end)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var type = _view.ReadByte((long)offset);
            var size = _view.ReadUInt64((long)offset + 8);

            // Space journald allocated but never wrote to: the normal end of an unclosed file.
            if (type == 0 && size == 0) break;

            if (size < ObjectHeaderSize || offset + size > end)
            {
                Warnings.Add($"object at 0x{offset:x} has an impossible size ({size}); stopped reading here");
                break;
            }

            if (type == ObjectEntry)
            {
                var entry = TryReadEntry(offset, size);
                if (entry is not null) yield return entry;
            }

            offset += (size + 7) & ~7UL;
        }
    }

    private JournalEntry? TryReadEntry(ulong offset, ulong size)
    {
        const int itemsStart = 64;
        var itemSize = Compact ? 4UL : 16UL;
        if (size < itemsStart) { Warnings.Add($"entry at 0x{offset:x} is truncated"); return null; }

        var o = (long)offset;
        var bootBytes = new byte[16];
        _view.ReadArray(o + 40, bootBytes, 0, 16);

        var count = (size - itemsStart) / itemSize;
        var fields = new List<KeyValuePair<string, byte[]>>((int)Math.Min(count, 256));

        var unreadable = 0;
        for (ulong i = 0; i < count; i++)
        {
            var at = o + itemsStart + (long)(i * itemSize);
            var dataOffset = Compact ? _view.ReadUInt32(at) : _view.ReadUInt64(at);
            var field = TryReadData(dataOffset);
            if (field is null) { unreadable++; continue; }
            fields.Add(field.Value);
        }

        // Keep what could be read. The timestamp and the surviving fields still place the event,
        // and dropping the whole entry would hide that anything was there at all.
        if (unreadable > 0)
        {
            Warnings.Add($"entry at 0x{offset:x} has {unreadable} unreadable field(s); kept, marked __AF_UNREADABLE_FIELDS");
            fields.Add(new("__AF_UNREADABLE_FIELDS", System.Text.Encoding.ASCII.GetBytes(unreadable.ToString())));
        }

        return new JournalEntry
        {
            Seqnum = _view.ReadUInt64(o + 16),
            RealtimeUsec = _view.ReadUInt64(o + 24),
            MonotonicUsec = _view.ReadUInt64(o + 32),
            BootId = Convert.ToHexString(bootBytes).ToLowerInvariant(),
            Fields = fields,
            SourceFile = Name
        };
    }

    private KeyValuePair<string, byte[]>? TryReadData(ulong offset)
    {
        if (_dataCache.TryGetValue(offset, out var cached)) return cached;

        if (offset < HeaderSize || offset + ObjectHeaderSize > (ulong)_length) return null;
        var o = (long)offset;
        if (_view.ReadByte(o) != ObjectData) return null;

        var flags = _view.ReadByte(o + 1);
        var size = _view.ReadUInt64(o + 8);
        var payloadStart = Compact ? 72UL : 64UL;
        if (size < payloadStart || offset + size > (ulong)_length) return null;

        var raw = new byte[size - payloadStart];
        _view.ReadArray(o + (long)payloadStart, raw, 0, raw.Length);

        byte[] payload;
        try
        {
            if ((flags & ObjectCompressedZstd) != 0) payload = DecompressZstd(raw);
            else if ((flags & ObjectCompressedLz4) != 0) payload = DecompressLz4(raw);
            else if ((flags & ObjectCompressedXz) != 0)
            {
                // Keep the field name, which precedes nothing we can read: the name is inside the
                // compressed payload too. Report it rather than invent a value.
                UndecodedFields++;
                payload = "__AF_UNDECODED=xz-compressed field, not decoded"u8.ToArray();
            }
            else payload = raw;
        }
        catch (Exception ex)
        {
            Warnings.Add($"data at 0x{offset:x} failed to decompress: {ex.Message}");
            return null;
        }

        var eq = Array.IndexOf(payload, (byte)'=');
        if (eq <= 0) return null;

        var result = new KeyValuePair<string, byte[]>(
            System.Text.Encoding.ASCII.GetString(payload, 0, eq),
            payload[(eq + 1)..]);

        // Common values - hostname, boot id, unit - are shared by thousands of entries. Bound the
        // cache so a multi-gigabyte journal cannot grow it without limit.
        if (_dataCache.Count >= 200_000) _dataCache.Clear();
        _dataCache[offset] = result;
        return result;
    }

    private byte[] DecompressZstd(byte[] raw)
    {
        _zstd ??= new Decompressor();
        try { return _zstd.Unwrap(raw).ToArray(); }
        catch
        {
            // A frame without a declared content size cannot be unwrapped in one call.
            using var input = new MemoryStream(raw);
            using var stream = new DecompressionStream(input);
            using var output = new MemoryStream();
            stream.CopyTo(output);
            return output.ToArray();
        }
    }

    /// <summary>systemd prefixes the LZ4 block with its decompressed size, as a little-endian u64.</summary>
    private static byte[] DecompressLz4(byte[] raw)
    {
        if (raw.Length < 8) throw new InvalidDataException("LZ4 payload shorter than its size prefix");
        var length = BitConverter.ToUInt64(raw, 0);
        if (length > int.MaxValue) throw new InvalidDataException($"LZ4 declared size {length} is not plausible");
        return Lz4Block.Decode(raw.AsSpan(8), (int)length);
    }

    public void Dispose()
    {
        _zstd?.Dispose();
        _view.Dispose();
        _map.Dispose();
    }
}

/// <summary>Decoder for the LZ4 block format, which is all systemd's journal uses.</summary>
public static class Lz4Block
{
    public static byte[] Decode(ReadOnlySpan<byte> source, int outputLength)
    {
        var output = new byte[outputLength];
        int s = 0, d = 0;

        while (s < source.Length)
        {
            int token = source[s++];

            var literals = token >> 4;
            if (literals == 15) literals += ReadLength(source, ref s);
            if (s + literals > source.Length || d + literals > outputLength)
                throw new InvalidDataException("LZ4 literal run overruns the buffer");
            source.Slice(s, literals).CopyTo(output.AsSpan(d));
            s += literals;
            d += literals;

            // The last sequence carries literals only.
            if (s >= source.Length) break;

            if (s + 2 > source.Length) throw new InvalidDataException("LZ4 match offset truncated");
            var offset = source[s] | (source[s + 1] << 8);
            s += 2;
            if (offset == 0 || offset > d) throw new InvalidDataException("LZ4 match offset out of range");

            var match = token & 15;
            if (match == 15) match += ReadLength(source, ref s);
            match += 4;
            if (d + match > outputLength) throw new InvalidDataException("LZ4 match overruns the buffer");

            // Byte by byte: a match may overlap the bytes it is producing, which is how runs encode.
            for (var i = 0; i < match; i++) output[d + i] = output[d - offset + i];
            d += match;
        }

        if (d != outputLength)
            throw new InvalidDataException($"LZ4 produced {d} bytes, expected {outputLength}");
        return output;
    }

    private static int ReadLength(ReadOnlySpan<byte> source, ref int s)
    {
        var total = 0;
        byte b;
        do
        {
            if (s >= source.Length) throw new InvalidDataException("LZ4 length truncated");
            b = source[s++];
            total += b;
        } while (b == 255);
        return total;
    }
}

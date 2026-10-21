using System.Formats.Tar;
using System.IO.Compression;

namespace ArtefactForge.Core;

/// <summary>What a source entry is. Only a tar, or a zip made on Unix, holds anything but files and folders.</summary>
internal enum SourceEntryKind
{
    File,
    Directory,
    /// <summary>A symbolic link. Its target is in <see cref="SourceEntry.LinkTarget"/>; nothing is read through it.</summary>
    SymbolicLink,
    /// <summary>A tar hard link: the same content as the earlier entry named in <see cref="SourceEntry.LinkTarget"/>.</summary>
    HardLink,
    /// <summary>A device, pipe or socket. These hold no content to copy.</summary>
    Special,
    /// <summary>An entry this build cannot reproduce faithfully, such as a GNU sparse file.</summary>
    Unsupported
}

/// <summary>
/// One file in a collection source: an entry in a zip or tar, or a file in a collector's output folder.
/// </summary>
internal sealed class SourceEntry
{
    /// <summary>Path relative to the source, with '/' separators, as a zip names its entries.</summary>
    public required string FullName { get; init; }
    public required long Length { get; init; }
    /// <summary>Null when unknown - zip's DOS timestamp of 1980, which collectors use for "unknown".</summary>
    public DateTime? LastWriteUtc { get; init; }
    /// <summary>The CRC the zip recorded. Null for a folder or a tar, where only the length can be checked.</summary>
    public uint? Crc32 { get; init; }
    public required Func<Stream> Open { get; init; }
    public SourceEntryKind Kind { get; init; } = SourceEntryKind.File;
    /// <summary>A symbolic link's target as recorded, or the entry a hard link repeats.</summary>
    public string? LinkTarget { get; init; }
    public bool IsDirectory => Kind == SourceEntryKind.Directory || FullName.EndsWith('/');
}

/// <summary>
/// A zip, a tar (gzip-compressed or not), or a folder holding what a collector's archive held (a
/// Velociraptor or UAC collection someone has already unpacked). The folder is only ever read:
/// files are opened read-only and shared.
/// </summary>
internal sealed class CollectionSource : IDisposable
{
    private readonly ZipArchive? _zip;
    private readonly TarCursor? _tar;
    private readonly Dictionary<string, SourceEntry> _byName;

    public string Path { get; }
    public bool IsFolder => _zip is null && _tar is null;
    public bool IsTar => _tar is not null;
    public IReadOnlyList<SourceEntry> Entries { get; }

    /// <summary>
    /// Set when the source itself is damaged - a tar or gzip stream that ends early or fails its
    /// checksum. Entries read before that point are listed; the last of them may be short.
    /// </summary>
    public string? Damage { get; }

    private CollectionSource(string path, ZipArchive? zip, TarCursor? tar, List<SourceEntry> entries, string? damage = null)
    {
        Path = path;
        _zip = zip;
        _tar = tar;
        Entries = entries;
        Damage = damage;
        _byName = new Dictionary<string, SourceEntry>(StringComparer.Ordinal);
        foreach (var entry in entries) _byName.TryAdd(entry.FullName, entry);
    }

    public static CollectionSource Open(string path)
    {
        if (Directory.Exists(path))
        {
            var root = System.IO.Path.GetFullPath(path).TrimEnd(System.IO.Path.DirectorySeparatorChar);
            // Links are listed but not descended into (enumeration does not follow them), so a
            // linked folder appears once, as a link, rather than vanishing.
            var entries = new DirectoryInfo(root).EnumerateFileSystemInfos("*", SearchOption.AllDirectories)
                .Where(info => info is FileInfo || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                .Select(info =>
                {
                    var name = info.FullName[(root.Length + 1)..].Replace('\\', '/');
                    // A link in an unpacked collection is recorded, never followed: its target can
                    // be anywhere on this machine, outside the evidence.
                    if (info.Attributes.HasFlag(FileAttributes.ReparsePoint) || info is not FileInfo file)
                        return new SourceEntry
                        {
                            FullName = name, Length = 0, Kind = SourceEntryKind.SymbolicLink,
                            LinkTarget = info.LinkTarget, LastWriteUtc = info.LastWriteTimeUtc, Open = () => Stream.Null
                        };
                    return new SourceEntry
                    {
                        FullName = name,
                        Length = file.Length,
                        LastWriteUtc = file.LastWriteTimeUtc,
                        Open = () => new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                                                    1 << 16, useAsync: true)
                    };
                })
                .ToList();
            return new CollectionSource(root, null, null, entries);
        }

        var full = System.IO.Path.GetFullPath(path);
        if (IsTarFile(full))
        {
            var cursor = new TarCursor(full);
            var (entries, damage) = cursor.List();
            return new CollectionSource(full, null, cursor, entries, damage);
        }

        var zip = ZipFile.OpenRead(path);
        return new CollectionSource(full, zip, null, zip.Entries.Select(ZipEntry).ToList());
    }

    private static SourceEntry ZipEntry(ZipArchiveEntry e)
    {
        var entry = new SourceEntry
        {
            FullName = e.FullName.Replace('\\', '/'),
            Length = e.Length,
            LastWriteUtc = e.LastWriteTime.Year > 1980 ? e.LastWriteTime.UtcDateTime : null,
            Crc32 = e.Crc32,
            Open = e.Open
        };

        // A zip made on Unix keeps the file mode in the high half of the external attributes, and
        // stores a symbolic link as an entry whose content is the target. Written out as a file,
        // the link would become a small text file posing as /etc/localtime.
        const int typeMask = 0xF000, symlink = 0xA000;
        if (((e.ExternalAttributes >> 16) & typeMask) != symlink || e.Length > 4096) return entry;

        using var reader = new StreamReader(e.Open());
        return new SourceEntry
        {
            FullName = entry.FullName, Length = 0, LastWriteUtc = entry.LastWriteUtc,
            Kind = SourceEntryKind.SymbolicLink, LinkTarget = reader.ReadToEnd(), Open = () => Stream.Null
        };
    }

    /// <summary>Opens a file by its source-relative name, or null when there is none.</summary>
    public Stream? OpenByName(string name) => _byName.TryGetValue(name, out var entry) ? entry.Open() : null;

    public void Dispose()
    {
        _zip?.Dispose();
        _tar?.Dispose();
    }

    /// <summary>The archive types this build can unpack, by file name.</summary>
    public static bool IsArchiveName(string path) =>
        path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) || IsTarName(path);

    private static bool IsTarName(string path) =>
        path.EndsWith(".tar", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A tar is told from a zip by its content, not its name: a zip starts "PK". Anything else
    /// named as a tar is read as one, and fails as one if it is not.
    /// </summary>
    public static bool IsTarFile(string path)
    {
        if (!IsTarName(path)) return false;
        Span<byte> magic = stackalloc byte[2];
        using var stream = File.OpenRead(path);
        return stream.Read(magic) < 2 || magic[0] != 'P' || magic[1] != 'K';
    }

    /// <summary>The archive's name without its extension, both parts of it for ".tar.gz".</summary>
    public static string Stem(string path)
    {
        var name = System.IO.Path.GetFileName(path.TrimEnd(System.IO.Path.DirectorySeparatorChar));
        if (Directory.Exists(path)) return name;
        foreach (var extension in (string[])[".tar.gz", ".tgz", ".tar", ".zip"])
            if (name.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) return name[..^extension.Length];
        return System.IO.Path.GetFileNameWithoutExtension(name);
    }

    /// <summary>
    /// Reads entry headers from a tar, front to back. Used to recognise a collection without
    /// unpacking it; the caller stops as soon as it knows enough.
    /// </summary>
    public static IEnumerable<(SourceEntry Entry, Func<Stream?> Data)> ReadTarHeaders(string path)
    {
        using var cursor = new TarCursor(path);
        foreach (var item in cursor.Walk()) yield return item;
    }

    /// <summary>
    /// Forward-only access to a tar. A compressed tar cannot seek, so entries are opened in the order
    /// they are stored; asking for an earlier one starts again from the top. The extractor reads them
    /// in order, so in practice the archive is read twice: once to list it and once to unpack it.
    /// </summary>
    private sealed class TarCursor(string path) : IDisposable
    {
        private TarStream? _stream;
        private TarReader? _reader;
        private Stream? _data;
        private int _position = -1;

        public (List<SourceEntry> Entries, string? Damage) List()
        {
            var entries = new List<SourceEntry>();
            try
            {
                foreach (var (entry, _) in Walk()) entries.Add(entry);
                return (entries, null);
            }
            catch (Exception ex) when (ex is EndOfStreamException or InvalidDataException or FormatException)
            {
                return (entries, Damaged(ex));
            }
        }

        public IEnumerable<(SourceEntry Entry, Func<Stream?> Data)> Walk()
        {
            Restart();
            while (Next() is { } tar)
            {
                if (tar.EntryType is TarEntryType.GlobalExtendedAttributes) continue;

                var name = Normalise(tar.Name);
                if (name.Length == 0) continue;
                var at = _position;
                var kind = Kind(tar.EntryType);
                var stream = tar.DataStream;
                yield return (new SourceEntry
                {
                    FullName = kind == SourceEntryKind.Directory && !name.EndsWith('/') ? name + "/" : name,
                    Length = kind == SourceEntryKind.File ? tar.Length : 0,
                    LastWriteUtc = tar.ModificationTime.UtcDateTime,
                    Kind = kind,
                    // A hard link names another entry in the archive; a symbolic link names a path
                    // on the source system and is kept exactly as recorded.
                    LinkTarget = kind switch
                    {
                        SourceEntryKind.HardLink => Normalise(tar.LinkName),
                        SourceEntryKind.SymbolicLink => tar.LinkName,
                        _ => null
                    },
                    Open = () => OpenAt(at)
                }, () => stream is null ? null : new Unclosed(stream));
            }

            // Reaching the end proves the tar is whole, but not the gzip around it: a gzip cut
            // within its 8-byte trailer still decompresses in full, so the trailer is checked here.
            _stream!.DrainAndVerify();
        }

        private Stream OpenAt(int index)
        {
            if (_reader is null || index <= _position) Restart();
            TarEntry? tar = null;
            while (_position < index)
                tar = Next() ?? throw new EndOfStreamException("the tar ended before entry " + index);
            return tar?.DataStream is { } data ? new Unclosed(data) : Stream.Null;
        }

        /// <summary>
        /// Moves to the next entry, first reading whatever is left of the current one. TarReader's
        /// own skip of unread data loses its place on a stream that cannot seek - a .tar.gz - and
        /// misreads the next header (.NET 9, reproduced with a 1-byte entry), so it is never used.
        /// </summary>
        private TarEntry? Next()
        {
            _data?.CopyTo(Stream.Null);
            var tar = _reader!.GetNextEntry();
            _data = tar?.DataStream;
            _position++;
            return tar;
        }

        private void Restart()
        {
            Dispose();
            _stream = new TarStream(path);
            _reader = new TarReader(_stream.Data, leaveOpen: true);
            _data = null;
            _position = -1;
        }

        public void Dispose()
        {
            _reader?.Dispose();
            _stream?.Dispose();
            _reader = null;
            _stream = null;
        }

        private static SourceEntryKind Kind(TarEntryType type) => type switch
        {
            TarEntryType.RegularFile or TarEntryType.V7RegularFile or TarEntryType.ContiguousFile => SourceEntryKind.File,
            TarEntryType.Directory => SourceEntryKind.Directory,
            TarEntryType.SymbolicLink => SourceEntryKind.SymbolicLink,
            TarEntryType.HardLink => SourceEntryKind.HardLink,
            TarEntryType.CharacterDevice or TarEntryType.BlockDevice or TarEntryType.Fifo => SourceEntryKind.Special,
            _ => SourceEntryKind.Unsupported
        };

        /// <summary>
        /// tar names entries "./etc/passwd" or "/etc/passwd" as often as "etc/passwd". A '\' is left
        /// alone: on Unix it is part of a name.
        /// </summary>
        public static string Normalise(string name)
        {
            var n = name;
            while (n.StartsWith("./", StringComparison.Ordinal)) n = n[2..];
            return n.TrimStart('/');
        }
    }

    /// <summary>Turns a reader failure into what the analyst needs to know.</summary>
    internal static string Damaged(Exception ex) => ex switch
    {
        EndOfStreamException => "the archive ends before its last entry is complete - file truncated? "
                                + "Entries up to that point were read.",
        // .NET reports a failed gzip checksum as an "unsupported compression method".
        InvalidDataException => "the compressed data is corrupt or fails its checksum (" + ex.Message + ")",
        _ => "the archive could not be read: " + ex.Message
    };

    /// <summary>
    /// The decompressed bytes of a tar, with the gzip trailer checked at the end. .NET checks a
    /// trailer it finds but says nothing when there is none, which is how a file cut a few bytes
    /// short would pass. The trailer is compared with the CRC-32 and length of what was read.
    /// </summary>
    private sealed class TarStream : IDisposable
    {
        private readonly FileStream _file;
        private readonly Counting _counting;
        private readonly bool _gzip;
        private readonly long _length;

        public Stream Data { get; }

        public TarStream(string path)
        {
            _file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
            _length = _file.Length;
            Span<byte> magic = stackalloc byte[2];
            var gzip = _file.Read(magic) == 2 && magic[0] == 0x1F && magic[1] == 0x8B;
            _file.Position = 0;
            _gzip = gzip;
            _counting = new Counting(gzip ? new GZipStream(_file, CompressionMode.Decompress, leaveOpen: true)
                                          : new Unclosed(_file));
            Data = _counting;
        }

        public void DrainAndVerify()
        {
            if (!_gzip) return;

            // Past the tar's end-of-archive blocks there may be padding; read it so the
            // decompressor reaches the trailer.
            var buffer = new byte[1 << 16];
            while (_counting.Read(buffer) > 0) { }

            Span<byte> trailer = stackalloc byte[8];
            _file.Position = _length - 8;
            _file.ReadExactly(trailer);
            var crc = BitConverter.ToUInt32(trailer[..4]);
            var size = BitConverter.ToUInt32(trailer[4..]);
            if (crc != _counting.Crc || size != (uint)_counting.Count)
                throw new InvalidDataException("the gzip trailer does not match the data - file truncated?");
        }

        public void Dispose()
        {
            _counting.Dispose();
            _file.Dispose();
        }
    }

    /// <summary>Counts and checksums what is read through it.</summary>
    private sealed class Counting(Stream inner) : Stream
    {
        private readonly System.IO.Hashing.Crc32 _crc = new();
        public uint Crc => _crc.GetCurrentHashAsUInt32();
        public long Count { get; private set; }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var n = inner.Read(buffer);
            _crc.Append(buffer[..n]);
            Count += n;
            return n;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => Count; set => throw new NotSupportedException(); }
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

    /// <summary>
    /// An entry's data, handed to a caller who disposes it. The tar reader still owns the stream and
    /// skips whatever was not read when it moves to the next entry, so disposing must not close it.
    /// </summary>
    private sealed class Unclosed(Stream inner) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => inner.Read(buffer);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(buffer, cancellationToken);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

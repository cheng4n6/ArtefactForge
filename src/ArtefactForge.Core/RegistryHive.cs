using System.Buffers.Binary;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArtefactForge.Core;

/// <summary>
/// A minimal, read-only reader for offline registry hive files (regf), enough to look up a key by
/// path and read a string or DWORD value. It exists so detection can name a mounted image after
/// its host without running a tool: parsing proper is RECmd's job.
///
/// Reads go straight to the file at the offsets the cells name; nothing is cached and nothing is
/// written. Transaction logs are not replayed, so a dirty hive reads as of its last flush - good
/// enough for a value that changes as rarely as the computer name.
/// </summary>
public sealed class RegistryHive : IDisposable
{
    private const int BaseBlockSize = 0x1000;
    private const ushort CompressedName = 0x20;

    private readonly SafeFileHandle handle;
    private readonly long length;
    private readonly int rootCell;

    private RegistryHive(SafeFileHandle handle, long length, int rootCell)
    {
        this.handle = handle;
        this.length = length;
        this.rootCell = rootCell;
    }

    /// <summary>
    /// Opens a hive for reading, sharing it with anything else that has it open. Throws
    /// <see cref="InvalidDataException"/> if the file is not a regf hive.
    /// </summary>
    public static RegistryHive Open(string path)
    {
        var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                                     FileShare.ReadWrite | FileShare.Delete);
        try
        {
            var length = RandomAccess.GetLength(handle);
            Span<byte> header = stackalloc byte[0x28];
            if (length < BaseBlockSize || RandomAccess.Read(handle, header, 0) < header.Length
                || !header[..4].SequenceEqual("regf"u8))
                throw new InvalidDataException("not a registry hive (no regf signature)");

            return new RegistryHive(handle, length, BinaryPrimitives.ReadInt32LittleEndian(header[0x24..]));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Reads a REG_SZ or REG_EXPAND_SZ value. Null when the key, the value or the data is missing,
    /// or the value holds another type.
    /// </summary>
    public string? ReadString(string keyPath, string valueName)
    {
        var data = ReadValue(keyPath, valueName, out var type);
        if (data is null || type is not (1 or 2)) return null;
        var text = Encoding.Unicode.GetString(data);
        var end = text.IndexOf('\0');
        return end >= 0 ? text[..end] : text;
    }

    /// <summary>Reads a REG_DWORD value, or null when it is missing or another type.</summary>
    public uint? ReadDword(string keyPath, string valueName)
    {
        var data = ReadValue(keyPath, valueName, out var type);
        return data is { Length: >= 4 } && type == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data) : null;
    }

    private byte[]? ReadValue(string keyPath, string valueName, out uint type)
    {
        type = 0;
        var key = FindKey(keyPath);
        if (key is null) return null;

        var count = BinaryPrimitives.ReadInt32LittleEndian(key.AsSpan(0x24));
        if (count <= 0) return null;
        var list = ReadCell(BinaryPrimitives.ReadInt32LittleEndian(key.AsSpan(0x28)));
        if (list is null) return null;

        for (var i = 0; i < count && (i + 1) * 4 <= list.Length; i++)
        {
            var vk = ReadCell(BinaryPrimitives.ReadInt32LittleEndian(list.AsSpan(i * 4)));
            if (vk is null || vk.Length < 0x14 || vk[0] != 'v' || vk[1] != 'k') continue;

            var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(vk.AsSpan(0x02));
            var compressed = (BinaryPrimitives.ReadUInt16LittleEndian(vk.AsSpan(0x10)) & 1) != 0;
            if (0x14 + nameLength > vk.Length) continue;
            var name = DecodeName(vk.AsSpan(0x14, nameLength), compressed);
            if (!string.Equals(name, valueName, StringComparison.OrdinalIgnoreCase)) continue;

            type = BinaryPrimitives.ReadUInt32LittleEndian(vk.AsSpan(0x0C));
            var size = BinaryPrimitives.ReadUInt32LittleEndian(vk.AsSpan(0x04));

            // The top bit means the data (four bytes at most) sits in the offset field itself.
            if ((size & 0x8000_0000) != 0)
                return vk.AsSpan(0x08, (int)Math.Min(size & 0x7FFF_FFFF, 4)).ToArray();

            var data = ReadCell(BinaryPrimitives.ReadInt32LittleEndian(vk.AsSpan(0x08)));
            // Data over 16 KB is split across a 'db' big-data list. Nothing read here is that
            // large, so it reads as missing rather than as a truncated value.
            if (data is null || size > data.Length) return null;
            return data[..(int)size];
        }
        return null;
    }

    private byte[]? FindKey(string keyPath)
    {
        var key = ReadCell(rootCell);
        foreach (var part in keyPath.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (key is null || !IsKey(key)) return null;
            key = FindSubkey(key, part);
        }
        return key is not null && IsKey(key) ? key : null;
    }

    private byte[]? FindSubkey(byte[] parent, string name)
    {
        var count = BinaryPrimitives.ReadInt32LittleEndian(parent.AsSpan(0x14));
        if (count <= 0) return null;
        return SearchList(BinaryPrimitives.ReadInt32LittleEndian(parent.AsSpan(0x1C)), name, depth: 0);
    }

    private byte[]? SearchList(int offset, string name, int depth)
    {
        var list = ReadCell(offset);
        if (list is null || list.Length < 4 || depth > 2) return null;

        var signature = Encoding.ASCII.GetString(list, 0, 2);
        var count = BinaryPrimitives.ReadUInt16LittleEndian(list.AsSpan(0x02));
        // lf and lh pair each offset with a hash; li and ri list bare offsets, ri pointing at
        // further lists rather than keys.
        var stride = signature is "lf" or "lh" ? 8 : signature is "li" or "ri" ? 4 : 0;
        if (stride == 0) return null;

        for (var i = 0; i < count && 4 + i * stride + 4 <= list.Length; i++)
        {
            var entry = BinaryPrimitives.ReadInt32LittleEndian(list.AsSpan(4 + i * stride));
            if (signature == "ri")
            {
                var found = SearchList(entry, name, depth + 1);
                if (found is not null) return found;
                continue;
            }

            var key = ReadCell(entry);
            if (key is not null && IsKey(key)
                && string.Equals(KeyName(key), name, StringComparison.OrdinalIgnoreCase))
                return key;
        }
        return null;
    }

    private static bool IsKey(byte[] cell) => cell.Length >= 0x4C && cell[0] == 'n' && cell[1] == 'k';

    private static string KeyName(byte[] key)
    {
        var length = BinaryPrimitives.ReadUInt16LittleEndian(key.AsSpan(0x48));
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(key.AsSpan(0x02));
        if (0x4C + length > key.Length) return string.Empty;
        return DecodeName(key.AsSpan(0x4C, length), (flags & CompressedName) != 0);
    }

    private static string DecodeName(ReadOnlySpan<byte> bytes, bool compressed) =>
        compressed ? Encoding.Latin1.GetString(bytes) : Encoding.Unicode.GetString(bytes);

    /// <summary>
    /// Returns the data of the cell at <paramref name="offset"/> (relative to the first hbin),
    /// without its size field. Null for an offset outside the file or a cell whose size makes no
    /// sense, so a damaged hive reads as missing values rather than throwing.
    /// </summary>
    private byte[]? ReadCell(int offset)
    {
        if (offset < 0) return null;
        long position = BaseBlockSize + (long)offset;
        if (position + 4 > length) return null;

        Span<byte> sizeBytes = stackalloc byte[4];
        if (RandomAccess.Read(handle, sizeBytes, position) < 4) return null;
        // Allocated cells carry a negative size; free ones are positive and hold nothing to read.
        var size = -BinaryPrimitives.ReadInt32LittleEndian(sizeBytes);
        if (size < 8 || size > 1024 * 1024 || position + size > length) return null;

        var data = new byte[size - 4];
        return RandomAccess.Read(handle, data, position + 4) == data.Length ? data : null;
    }

    public void Dispose() => handle.Dispose();
}

/// <summary>Reads the host name from a Windows installation's SYSTEM hive.</summary>
public static class WindowsHostName
{
    /// <summary>
    /// The ComputerName of the control set the system last booted with, or null when the hive is
    /// missing, unreadable or holds no usable name. Never throws: a name is a convenience for the
    /// analyst, and they can always rename the collection.
    /// </summary>
    public static string? FromRoot(string root)
    {
        var hivePath = Path.Combine(root, "Windows", "System32", "config", "SYSTEM");
        if (!File.Exists(hivePath)) return null;

        try
        {
            using var hive = RegistryHive.Open(hivePath);
            var current = hive.ReadDword("Select", "Current") ?? 1;
            var name = hive.ReadString(
                $@"ControlSet{current:D3}\Control\ComputerName\ComputerName", "ComputerName");
            return CollectionNaming.TryValidate(name, out var valid, out _) ? valid : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or InvalidDataException)
        {
            return null;
        }
    }
}

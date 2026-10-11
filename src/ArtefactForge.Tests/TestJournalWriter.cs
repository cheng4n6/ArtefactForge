using System.Text;
using ArtefactForge.Core.Linux;
using ZstdSharp;

namespace ArtefactForge.Tests;

public enum TestCompression { None, Zstd, Lz4 }

/// <summary>
/// Builds a minimal journal file in memory: header, data objects and entry objects, laid out as
/// journald lays them out. No hash tables or entry arrays - the reader walks objects and never
/// consults them, which is the point of testing it against a file that has none.
///
/// Evidence journals cannot be committed as fixtures - they carry hostnames and usernames - so
/// the tests build their own. The reader was separately validated against journalctl -o json on
/// a real Ubuntu 22.04 journal set.
/// </summary>
internal sealed class TestJournalWriter(bool compact = false)
{
    public const int HeaderSize = 256;

    private readonly MemoryStream _body = new();
    private int _entries;

    private ulong Next => HeaderSize + (ulong)_body.Length;

    public ulong AddData(string name, string value, TestCompression compression = TestCompression.None) =>
        AddData(name, Encoding.UTF8.GetBytes(value), compression);

    public ulong AddData(string name, byte[] value, TestCompression compression = TestCompression.None)
    {
        var payload = Encoding.ASCII.GetBytes(name + "=").Concat(value).ToArray();
        byte flags = 0;
        if (compression == TestCompression.Zstd)
        {
            using var compressor = new Compressor();
            payload = compressor.Wrap(payload).ToArray();
            flags = 4;
        }
        else if (compression == TestCompression.Lz4)
        {
            payload = BitConverter.GetBytes((ulong)payload.Length).Concat(Lz4LiteralsOnly(payload)).ToArray();
            flags = 2;
        }

        var offset = Next;
        var payloadStart = compact ? 72 : 64;
        var obj = new byte[payloadStart + payload.Length];
        obj[0] = 1;
        obj[1] = flags;
        BitConverter.GetBytes((ulong)obj.Length).CopyTo(obj, 8);
        payload.CopyTo(obj, payloadStart);
        Append(obj);
        return offset;
    }

    public ulong AddEntry(ulong seqnum, ulong realtimeUsec, params ulong[] data)
    {
        var itemSize = compact ? 4 : 16;
        var obj = new byte[64 + data.Length * itemSize];
        obj[0] = 3;
        BitConverter.GetBytes((ulong)obj.Length).CopyTo(obj, 8);
        BitConverter.GetBytes(seqnum).CopyTo(obj, 16);
        BitConverter.GetBytes(realtimeUsec).CopyTo(obj, 24);
        BitConverter.GetBytes(seqnum * 10).CopyTo(obj, 32);
        for (var i = 0; i < 16; i++) obj[40 + i] = 0xAB;
        for (var i = 0; i < data.Length; i++)
        {
            if (compact) BitConverter.GetBytes((uint)data[i]).CopyTo(obj, 64 + i * 4);
            else BitConverter.GetBytes(data[i]).CopyTo(obj, 64 + i * 16);
        }

        var offset = Next;
        Append(obj);
        _entries++;
        return offset;
    }

    /// <summary>Raw bytes appended as-is, for building damaged files.</summary>
    public void AppendRaw(byte[] bytes) => _body.Write(bytes);

    public byte[] Build(uint extraIncompatibleFlags = 0, byte state = 0, ulong? entryCount = null)
    {
        var header = new byte[HeaderSize];
        Encoding.ASCII.GetBytes("LPKSHHRH").CopyTo(header, 0);
        var flags = (uint)JournalFile.IncompatibleFlags.CompressedZstd | extraIncompatibleFlags;
        if (compact) flags |= (uint)JournalFile.IncompatibleFlags.Compact;
        BitConverter.GetBytes(flags).CopyTo(header, 12);
        header[16] = state;
        BitConverter.GetBytes((ulong)HeaderSize).CopyTo(header, 88);
        BitConverter.GetBytes((ulong)_body.Length).CopyTo(header, 96);
        BitConverter.GetBytes(entryCount ?? (ulong)_entries).CopyTo(header, 152);
        return header.Concat(_body.ToArray()).ToArray();
    }

    public string WriteTo(string path, uint extraIncompatibleFlags = 0)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, Build(extraIncompatibleFlags));
        return path;
    }

    private void Append(byte[] obj)
    {
        _body.Write(obj);
        var pad = (8 - obj.Length % 8) % 8;
        _body.Write(new byte[pad]);
    }

    /// <summary>A valid LZ4 block holding one literal run and no matches.</summary>
    public static byte[] Lz4LiteralsOnly(byte[] data)
    {
        var block = new List<byte>();
        if (data.Length < 15) block.Add((byte)(data.Length << 4));
        else
        {
            block.Add(0xF0);
            var rest = data.Length - 15;
            while (rest >= 255) { block.Add(255); rest -= 255; }
            block.Add((byte)rest);
        }
        block.AddRange(data);
        return block.ToArray();
    }
}

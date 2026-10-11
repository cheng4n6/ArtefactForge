using System.Buffers.Binary;
using System.Text;
using ArtefactForge.Core;

namespace ArtefactForge.Tests;

/// <summary>
/// The hive reader behind naming a mounted image. Hives are built here cell by cell to the regf
/// layout (base block, one hbin, nk/lf/li/ri/vk cells), so each list type and name encoding can be
/// exercised; a real SYSTEM hive cannot be committed.
/// </summary>
public class RegistryHiveTests
{
    private sealed record Key(string Name, Key[]? Subkeys = null, (string Name, uint Type, byte[] Data)[]? Values = null,
                              string ListType = "lh", bool Utf16Name = false);

    private static (string, uint, byte[]) Sz(string name, string value) =>
        (name, 1, Encoding.Unicode.GetBytes(value + "\0"));

    private static (string, uint, byte[]) Dword(string name, uint value)
    {
        var data = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(data, value);
        return (name, 4, data);
    }

    /// <summary>Writes <paramref name="root"/> as a hive file and returns its path.</summary>
    private static string WriteHive(string path, Key root)
    {
        var cells = new List<byte>();
        // hbin header: cells are addressed from the start of the first hbin.
        cells.AddRange("hbin"u8.ToArray());
        cells.AddRange(new byte[28]);

        int Cell(byte[] data)
        {
            var offset = cells.Count;
            var size = (data.Length + 4 + 7) & ~7;
            var sizeBytes = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(sizeBytes, -size);
            cells.AddRange(sizeBytes);
            cells.AddRange(data);
            cells.AddRange(new byte[size - 4 - data.Length]);
            return offset;
        }

        int WriteKey(Key key)
        {
            var subkeyOffsets = (key.Subkeys ?? []).Select(WriteKey).ToList();
            var listOffset = -1;
            if (subkeyOffsets.Count > 0)
            {
                if (key.ListType == "ri")
                {
                    // One li per subkey, under an ri: the shape a large key takes.
                    var lists = subkeyOffsets.Select(o => Cell(List("li", [o], 4))).ToList();
                    listOffset = Cell(List("ri", lists, 4));
                }
                else listOffset = Cell(List(key.ListType, subkeyOffsets, key.ListType == "li" ? 4 : 8));
            }

            var valueOffsets = (key.Values ?? []).Select(v =>
            {
                var name = Encoding.Latin1.GetBytes(v.Name);
                var vk = new byte[0x14 + name.Length];
                "vk"u8.CopyTo(vk);
                BinaryPrimitives.WriteUInt16LittleEndian(vk.AsSpan(0x02), (ushort)name.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(vk.AsSpan(0x0C), v.Type);
                BinaryPrimitives.WriteUInt16LittleEndian(vk.AsSpan(0x10), 1);
                name.CopyTo(vk, 0x14);
                if (v.Data.Length <= 4)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(vk.AsSpan(0x04), 0x8000_0000 | (uint)v.Data.Length);
                    v.Data.CopyTo(vk, 0x08);
                }
                else
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(vk.AsSpan(0x04), (uint)v.Data.Length);
                    BinaryPrimitives.WriteInt32LittleEndian(vk.AsSpan(0x08), Cell(v.Data));
                }
                return Cell(vk);
            }).ToList();

            var valuesList = -1;
            if (valueOffsets.Count > 0)
            {
                var data = new byte[valueOffsets.Count * 4];
                for (var i = 0; i < valueOffsets.Count; i++)
                    BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(i * 4), valueOffsets[i]);
                valuesList = Cell(data);
            }

            var keyName = key.Utf16Name ? Encoding.Unicode.GetBytes(key.Name) : Encoding.Latin1.GetBytes(key.Name);
            var nk = new byte[0x4C + keyName.Length];
            "nk"u8.CopyTo(nk);
            BinaryPrimitives.WriteUInt16LittleEndian(nk.AsSpan(0x02), (ushort)(key.Utf16Name ? 0 : 0x20));
            BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(0x14), subkeyOffsets.Count);
            BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(0x1C), listOffset);
            BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(0x24), valueOffsets.Count);
            BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(0x28), valuesList);
            BinaryPrimitives.WriteUInt16LittleEndian(nk.AsSpan(0x48), (ushort)keyName.Length);
            keyName.CopyTo(nk, 0x4C);
            return Cell(nk);
        }

        var rootOffset = WriteKey(root);
        var header = new byte[0x1000];
        "regf"u8.CopyTo(header);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(0x24), rootOffset);

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [.. header, .. cells]);
        return path;
    }

    private static byte[] List(string signature, List<int> offsets, int stride)
    {
        var data = new byte[4 + offsets.Count * stride];
        Encoding.ASCII.GetBytes(signature).CopyTo(data, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), (ushort)offsets.Count);
        for (var i = 0; i < offsets.Count; i++)
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(4 + i * stride), offsets[i]);
        return data;
    }

    private static Key SystemHive(uint current, string name, string listType = "lh") =>
        new("ROOT",
        [
            new Key("Select", Values: [Dword("Current", current), Dword("Default", current)]),
            new Key("ControlSet001", ListType: listType, Subkeys:
            [
                new Key("Control", ListType: listType, Subkeys:
                [
                    new Key("ComputerName", Subkeys:
                    [
                        new Key("ComputerName", Values: [Sz("ComputerName", "OLD-NAME")])
                    ])
                ])
            ]),
            new Key("ControlSet002", ListType: listType, Subkeys:
            [
                new Key("Control", Subkeys:
                [
                    new Key("ComputerName", Subkeys:
                    [
                        new Key("ComputerName", Values: [Sz("ComputerName", name)])
                    ])
                ])
            ])
        ]);

    private static string SystemPath(TempDirectory dir) =>
        Path.Combine(dir.Path, "Windows", "System32", "config", "SYSTEM");

    [Fact]
    public void Mounted_windows_volume_is_named_after_the_host_in_its_current_control_set()
    {
        using var dir = new TempDirectory();
        WriteHive(SystemPath(dir), SystemHive(current: 2, "WKSTN-042"));

        Assert.Equal("WKSTN-042", LayoutDetector.DriveRootName(dir.Path, "E"));
    }

    [Theory]
    [InlineData("li")]
    [InlineData("lf")]
    [InlineData("ri")]
    public void Subkeys_are_found_through_every_list_type(string listType)
    {
        using var dir = new TempDirectory();
        WriteHive(SystemPath(dir), SystemHive(current: 1, "UNUSED", listType));

        Assert.Equal("OLD-NAME", WindowsHostName.FromRoot(dir.Path));
    }

    [Fact]
    public void Key_and_value_lookups_ignore_case_and_read_utf16_key_names()
    {
        using var dir = new TempDirectory();
        var path = WriteHive(Path.Combine(dir.Path, "hive"),
            new Key("ROOT", [new Key("Größe", Utf16Name: true, Values: [Sz("Wert", "ok")])]));

        using var hive = RegistryHive.Open(path);
        Assert.Equal("ok", hive.ReadString("GRÖßE", "WERT"));
        Assert.Null(hive.ReadString("Missing", "Wert"));
        Assert.Null(hive.ReadDword("Größe", "Wert"));
    }

    [Fact]
    public void A_volume_without_a_usable_hive_keeps_the_drive_letter_name()
    {
        using var dir = new TempDirectory();
        Assert.Equal("IMAGE_F", LayoutDetector.DriveRootName(dir.Path, "F"));

        File.WriteAllText(dir.File(Path.Combine("Windows", "System32", "config", "SYSTEM")), "not a hive");
        Assert.Equal("IMAGE_F", LayoutDetector.DriveRootName(dir.Path, "F"));
    }

    [Fact]
    public void A_name_that_cannot_be_a_folder_is_not_used()
    {
        using var dir = new TempDirectory();
        WriteHive(SystemPath(dir), SystemHive(current: 2, "CON"));

        Assert.Equal("IMAGE_E", LayoutDetector.DriveRootName(dir.Path, "E"));
    }

    [Fact]
    public void A_truncated_hive_reads_as_missing_rather_than_throwing()
    {
        using var dir = new TempDirectory();
        var path = WriteHive(SystemPath(dir), SystemHive(current: 2, "WKSTN-042"));
        var bytes = File.ReadAllBytes(path);
        File.WriteAllBytes(path, bytes[..(bytes.Length - 200)]);

        Assert.Null(WindowsHostName.FromRoot(dir.Path));
    }
}

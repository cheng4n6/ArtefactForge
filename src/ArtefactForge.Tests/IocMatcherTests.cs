using ArtefactForge.Core.Ioc;

namespace ArtefactForge.Tests;

/// <summary>The matching rules from the IOC list: what counts as a hit, and the near misses that must not.</summary>
public class IocMatcherTests
{
    private static readonly CsvHeader Header =
        CsvHeader.Parse("TimeCreated,Computer,Path,SHA1,Hashes,Payload");

    private static bool Hit(IocType type, string value, string record) =>
        new IocMatcher([IocEntry.Create(type, value)]).Match(record, Header, out _).Count > 0;

    [Theory]
    [InlineData("2026-01-01,WS01,C:\\Temp\\ABC.exe,,,", true)]
    [InlineData("2026-01-01,WS01,\"c:\\users\\bob\\downloads\\abc.EXE\",,,", true)]
    [InlineData("2026-01-01,WS01,/home/bob/ABC.exe,,,", true)]
    [InlineData("2026-01-01,WS01,ABC.exe,,,", true)]
    [InlineData("2026-01-01,WS01,C:\\Temp\\XABC.exe,,,", false)]
    [InlineData("2026-01-01,WS01,C:\\Temp\\ABC.exe.bak,,,", false)]
    [InlineData("2026-01-01,WS01,C:\\Temp\\my_ABC.exe,,,", false)]
    public void File_names_match_on_the_name_alone_in_any_folder(string record, bool expected) =>
        Assert.Equal(expected, Hit(IocType.FileName, "ABC.exe", record));

    [Theory]
    [InlineData("x,WS01,C:\\Users\\Public\\run.ps1,,,", true)]
    [InlineData("x,WS01,c:/users/public/RUN.ps1,,,", true)]
    [InlineData("x,WS01,,,,\"{\"\"Image\"\":\"\"C:\\\\Users\\\\Public\\\\run.ps1\"\"}\"", true)]
    [InlineData("x,WS01,\\Device\\HarddiskVolume3\\Users\\Public\\run.ps1,,,", true)]
    [InlineData("x,WS01,C:\\Users\\Public\\run.ps1x,,,", false)]
    [InlineData("x,WS01,D:\\Other\\run.ps1,,,", false)]
    public void Paths_match_the_whole_path_whatever_the_separators(string record, bool expected) =>
        Assert.Equal(expected, Hit(IocType.Path, "C:\\Users\\Public\\run.ps1", record));

    [Theory]
    [InlineData("x,WS01,,0123456789ABCDEF0123456789ABCDEF01234567,,", true)]
    [InlineData("x,WS01,,00000123456789abcdef0123456789abcdef01234567,,", true)]
    [InlineData("x,WS01,,,\"SHA1=0123456789abcdef0123456789abcdef01234567,MD5=00\",", true)]
    [InlineData("x,WS01,,,,0123456789abcdef0123456789abcdef01234567", false)]
    [InlineData("x,WS01,,0123456789abcdef0123456789abcdef0123456789,,", false)]
    public void Hashes_match_only_in_hash_columns_as_a_whole_value(string record, bool expected) =>
        Assert.Equal(expected, Hit(IocType.Hash, "0123456789abcdef0123456789abcdef01234567", record));

    [Theory]
    [InlineData("x,WS01,,,,Connection to 10.0.0.1:443 refused", true)]
    [InlineData("x,10.0.0.1,,,,", true)]
    [InlineData("x,WS01,,,,Connection to 10.0.0.12", false)]
    [InlineData("x,WS01,,,,Connection to 110.0.0.1", false)]
    public void IPs_match_anywhere_in_a_line_as_a_whole_address(string record, bool expected) =>
        Assert.Equal(expected, Hit(IocType.IP, "10.0.0.1", record));

    [Theory]
    [InlineData("x,WS01,,,,GET http://evil.example/a", true)]
    [InlineData("x,WS01,,,,lookup cdn.EVIL.example.", true)]
    [InlineData("x,WS01,,,,lookup notevil.example", false)]
    [InlineData("x,WS01,,,,lookup evil.example.org", false)]
    public void Domains_match_anywhere_with_their_subdomains(string record, bool expected) =>
        Assert.Equal(expected, Hit(IocType.Domain, "evil.example", record));

    [Theory]
    [InlineData("x,WS01,,,,Logon by CORP\\alice", true)]
    [InlineData("x,WS01,,,,alice@corp.example", true)]
    [InlineData("x,WS01,,,,Logon by malice", false)]
    [InlineData("x,WS01,,,,Logon by alice.smith", false)]
    public void Accounts_match_anywhere_as_a_whole_name(string record, bool expected) =>
        Assert.Equal(expected, Hit(IocType.Account, "alice", record));

    [Fact]
    public void A_domain_qualified_account_matches_in_a_JSON_payload_too() =>
        Assert.True(Hit(IocType.Account, "CORP\\alice", "x,WS01,,,,\"{\"\"User\"\":\"\"CORP\\\\alice\"\"}\""));

    [Fact]
    public void Several_IOCs_in_one_line_are_all_reported()
    {
        var matcher = new IocMatcher(
        [
            IocEntry.Create(IocType.FileName, "ABC.exe"),
            IocEntry.Create(IocType.IP, "10.0.0.1"),
            IocEntry.Create(IocType.Account, "bob")
        ]);

        var found = matcher.Match("x,WS01,C:\\ABC.exe,,,connect 10.0.0.1", Header, out _);

        Assert.Equal(["ABC.exe", "10.0.0.1"], found.Select(f => f.Value));
    }

    [Theory]
    [InlineData("SHA1", true)]
    [InlineData("SHA-256", true)]
    [InlineData("Hashes", true)]
    [InlineData("MD5", true)]
    [InlineData("FileHash", true)]
    [InlineData("ShadowCopy", false)]
    [InlineData("SharedPath", false)]
    public void Hash_columns_are_found_by_their_names(string name, bool expected) =>
        Assert.Equal(expected, CsvHeader.IsHashColumn(name));

    [Fact]
    public void A_quoted_field_with_a_line_break_is_read_as_one_record()
    {
        var text = "A,B\nx,\"first line\nsecond line\"\ny,z\n";

        var records = CsvText.Records(new StringReader(text)).ToList();

        Assert.Equal(3, records.Count);
        Assert.Equal(2, records[1].LineNumber);
        Assert.Equal("second line", CsvText.Split(records[1].Text)[1].Split('\n')[1]);
        Assert.Equal(4, records[2].LineNumber);
    }
}

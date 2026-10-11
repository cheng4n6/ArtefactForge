using System.Globalization;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxLiveResponse module: what UAC's live_response commands recorded about the running
/// system at collection time - the state no log or file on disk holds.
///
///   LinuxLiveResponse_Processes.csv      ps, with the executable, working directory and hashes
///                                        from /proc, and a Review column
///   LinuxLiveResponse_Network.csv        sockets and their owning processes (ss, else netstat)
///   LinuxLiveResponse_Interfaces.csv     addresses per interface (ip addr)
///   LinuxLiveResponse_Routes.csv         routing table (ip route)
///   LinuxLiveResponse_Neighbours.csv     ARP/NDP cache (ip neighbor, else arp -a)
///   LinuxLiveResponse_OpenFiles.csv      lsof, with deleted-but-open files marked
///   LinuxLiveResponse_KernelModules.csv  loaded modules and their taint flags (/proc/modules, else lsmod)
///   LinuxLiveResponse_Index.csv          every live_response file, and which CSV (if any) read it
///
/// UAC names each output file after the command that made it (ps_auxwww.txt), so the file name
/// says which command ran. Where UAC ran several variants, the richest is read: the ps listing
/// with full start times over 'ps auxwww', 'ss -anp' over 'netstat -anp'. Everything not parsed
/// is still listed in the index, so nothing UAC captured is out of sight.
///
/// Times come from the collected system's own clock and timezone (ps prints local time); they
/// are written as recorded, in StartedLocal, not converted.
/// </summary>
public static partial class LiveResponseExport
{
    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        var live = Path.Combine(root, UacCollection.MetadataFolder, "live_response");
        if (!Directory.Exists(live))
        {
            log.WriteLine($"No live_response folder under {Path.Combine(root, UacCollection.MetadataFolder)}");
            return 0;
        }

        Directory.CreateDirectory(outputDirectory);
        var parsed = new Dictionary<string, string>(StringComparer.Ordinal);
        var context = new Context(root, live, outputDirectory, errors, parsed);

        var outputs = new List<CsvFile>
        {
            Processes(context, cancellationToken),
            Network(context),
            Interfaces(context),
            Routes(context),
            Neighbours(context),
            OpenFiles(context, cancellationToken),
            KernelModules(context)
        };
        outputs.Add(Index(context));

        foreach (var csv in outputs)
        {
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-40} {csv.Rows} row(s)");
            csv.Dispose();
        }
        return 0;
    }

    private sealed record Context(string Root, string Live, string Out, TextWriter Errors, Dictionary<string, string> Parsed)
    {
        public string? Find(params string[] relatives) =>
            relatives.Select(r => Path.Combine([Live, .. r.Split('/')])).FirstOrDefault(File.Exists);

        public string Source(string path) => Path.GetRelativePath(Root, path).Replace('\\', '/');

        public CsvFile Csv(string name, params string[] header) => new(Path.Combine(Out, name), header);

        /// <summary>
        /// Reports lines of a known format that could not be read, so a variant the parser does
        /// not understand is seen rather than producing a short table that looks whole.
        /// </summary>
        public void Unread(string path, int lines, string format)
        {
            if (lines > 0)
                Errors.WriteLine($"{Source(path)}: {lines} line(s) not in the expected {format} format - not parsed");
        }
    }

    // --- processes ---------------------------------------------------------------------------

    private sealed class ProcInfo
    {
        public string Exe = "", Cwd = "", Md5 = "", Sha1 = "", Sha256 = "";
        public bool ExeDeleted;
    }

    private static CsvFile Processes(Context c, CancellationToken cancellationToken)
    {
        var csv = c.Csv("LinuxLiveResponse_Processes.csv",
            "PID", "PPID", "User", "StartedLocal", "Elapsed", "State", "TTY", "CPU", "Memory",
            "CommandLine", "Exe", "ExeDeleted", "Cwd", "ExeMD5", "ExeSHA1", "ExeSHA256", "Review", "SourceFile");

        var proc = ProcDetails(c);
        var (path, format) = c.Find("process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_lstart_args.txt") is { } a ? (a, "lstart")
            : c.Find("process/ps_-eo_user_pid_ppid_pcpu_pmem_tty_stat_etime_args.txt") is { } b ? (b, "etime")
            : c.Find("process/ps_auxwww.txt") is { } d ? (d, "aux")
            : c.Find("process/ps_-ef.txt") is { } e ? (e, "ef")
            : ((string?)null, "");
        if (path is null) return csv;

        c.Parsed[path] = csv.FileName;
        var unread = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in File.ReadLines(path).Skip(1))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(line)) continue;

            string pid, ppid = "", user, started = "", elapsed = "", state = "", tty, cpu = "", mem = "", args;
            switch (format)
            {
                case "lstart":
                {
                    // USER PID PPID %CPU %MEM TT STAT STARTED(5 words: Sun Oct 11 10:00:00 2026) COMMAND
                    var (t, rest) = Fields(line, 12);
                    if (t is null) { unread++; continue; }
                    (user, pid, ppid, cpu, mem, tty, state) = (t[0], t[1], t[2], t[3], t[4], t[5], t[6]);
                    started = LStart(string.Join(' ', t[7..12])) ?? string.Join(' ', t[7..12]);
                    args = rest;
                    break;
                }
                case "etime":
                {
                    var (t, rest) = Fields(line, 8);
                    if (t is null) { unread++; continue; }
                    (user, pid, ppid, cpu, mem, tty, state, elapsed) = (t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
                    args = rest;
                    break;
                }
                case "aux":
                {
                    // USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                    var (t, rest) = Fields(line, 10);
                    if (t is null) { unread++; continue; }
                    (user, pid, cpu, mem, tty, state, started) = (t[0], t[1], t[2], t[3], t[6], t[7], t[8]);
                    args = rest;
                    break;
                }
                default:
                {
                    // UID PID PPID C STIME TTY TIME CMD
                    var (t, rest) = Fields(line, 7);
                    if (t is null) { unread++; continue; }
                    (user, pid, ppid, started, tty) = (t[0], t[1], t[2], t[4], t[5]);
                    args = rest;
                    break;
                }
            }

            if (!pid.All(char.IsAsciiDigit)) { unread++; continue; }
            // The ps that UAC itself ran, and its shell, appear in the listing; they are kept, as
            // the analyst may want to see the collection happening.
            seen.Add(pid);
            proc.TryGetValue(pid, out var info);
            csv.Write(pid, ppid, user, started, elapsed, state, tty, cpu, mem, args,
                      info?.Exe ?? "", info is { ExeDeleted: true } ? "yes" : "", info?.Cwd ?? "",
                      info?.Md5 ?? "", info?.Sha1 ?? "", info?.Sha256 ?? "",
                      Review(args, info), c.Source(path));
        }
        c.Unread(path, unread, "ps");

        // A process /proc knew about but ps did not list is worth seeing: it may have started or
        // ended between the two commands, or ps may have been made to hide it.
        foreach (var (pid, info) in proc.Where(p => !seen.Contains(p.Key) && p.Value.Exe.Length > 0)
                                        .OrderBy(p => int.TryParse(p.Key, out var n) ? n : int.MaxValue))
        {
            csv.Write(pid, "", "", "", "", "", "", "", "", "", info.Exe, info.ExeDeleted ? "yes" : "", info.Cwd,
                      info.Md5, info.Sha1, info.Sha256,
                      string.Join("; ", new[] { "in /proc but not in ps", Review("", info) }.Where(r => r.Length > 0)),
                      "process/ls_-l_proc.txt");
        }
        return csv;
    }

    /// <summary>What about a process is worth a second look. Empty for most.</summary>
    private static string Review(string args, ProcInfo? info)
    {
        var reasons = new List<string>();
        if (info is { ExeDeleted: true }) reasons.Add("executable deleted while running");
        var exe = info?.Exe ?? "";
        var command = exe.Length > 0 ? exe : args.Split(' ', 2)[0];
        if (TempPath().IsMatch(command)) reasons.Add("runs from a temporary or shared-memory folder");
        if (Memfd().IsMatch(exe)) reasons.Add("runs from memory (memfd)");
        if (ReverseShell().IsMatch(args)) reasons.Add("command line looks like a shell or download one-liner");
        return string.Join("; ", reasons);
    }

    [GeneratedRegex(@"^/(tmp|var/tmp|dev/shm|run/shm)/")]
    private static partial Regex TempPath();

    [GeneratedRegex(@"memfd:")]
    private static partial Regex Memfd();

    [GeneratedRegex(@"/dev/tcp/|\bnc(at)?\b.*\s-e\s|\bbash -i\b|\bpython[0-9.]* -c\b|\bperl -e\b|base64 -d|\bcurl\b.*\|\s*(ba)?sh|\bwget\b.*\|\s*(ba)?sh")]
    private static partial Regex ReverseShell();

    /// <summary>
    /// The executable and working directory of each process, from 'ls -l /proc/[0-9]*', and its
    /// hashes from UAC's hash_running_processes.&lt;algorithm&gt;.
    /// </summary>
    private static Dictionary<string, ProcInfo> ProcDetails(Context c)
    {
        var result = new Dictionary<string, ProcInfo>(StringComparer.Ordinal);
        ProcInfo Get(string pid) => result.TryGetValue(pid, out var p) ? p : result[pid] = new ProcInfo();

        if (c.Find("process/ls_-l_proc.txt") is { } listing)
        {
            c.Parsed[listing] = "LinuxLiveResponse_Processes.csv";
            string? pid = null;
            foreach (var line in File.ReadLines(listing))
            {
                var header = ProcHeader().Match(line);
                if (header.Success) { pid = header.Groups[1].Value; continue; }
                if (pid is null || !line.StartsWith('l')) continue;

                var arrow = line.IndexOf(" -> ", StringComparison.Ordinal);
                if (arrow < 0) continue;
                var name = line[..arrow].Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
                var target = line[(arrow + 4)..];
                if (name == "exe")
                {
                    var info = Get(pid);
                    info.ExeDeleted = target.EndsWith(" (deleted)", StringComparison.Ordinal);
                    info.Exe = info.ExeDeleted ? target[..^" (deleted)".Length] : target;
                }
                else if (name == "cwd") Get(pid).Cwd = target;
            }
        }

        foreach (var (algorithm, set) in new (string, Action<ProcInfo, string>)[]
                 {
                     ("md5", (p, h) => p.Md5 = h), ("sha1", (p, h) => p.Sha1 = h), ("sha256", (p, h) => p.Sha256 = h)
                 })
        {
            if (c.Find($"process/hash_running_processes.{algorithm}") is not { } hashes) continue;
            c.Parsed[hashes] = "LinuxLiveResponse_Processes.csv";
            foreach (var (hash, file) in HashLines(hashes))
            {
                var m = ProcExe().Match(file);
                if (m.Success) set(Get(m.Groups[1].Value), hash);
            }
        }
        return result;
    }

    [GeneratedRegex(@"^/proc/(\d+):\s*$")]
    private static partial Regex ProcHeader();

    [GeneratedRegex(@"^/proc/(\d+)/(exe|file|path/a\.out|object/a\.out)$")]
    private static partial Regex ProcExe();

    /// <summary>
    /// md5sum style ("hash  path") or BSD style ("MD5 (path) = hash"), as UAC writes whichever
    /// tool the system has.
    /// </summary>
    internal static IEnumerable<(string Hash, string Path)> HashLines(string file)
    {
        foreach (var line in File.ReadLines(file))
        {
            var bsd = BsdHash().Match(line);
            if (bsd.Success) { yield return (bsd.Groups[2].Value.ToLowerInvariant(), bsd.Groups[1].Value); continue; }
            var gnu = GnuHash().Match(line);
            if (gnu.Success) yield return (gnu.Groups[1].Value.ToLowerInvariant(), gnu.Groups[2].Value);
        }
    }

    [GeneratedRegex(@"^[A-Z0-9]+ \((.*)\) = ([0-9a-fA-F]+)$")]
    private static partial Regex BsdHash();

    [GeneratedRegex(@"^\\?([0-9a-fA-F]{32,128}) [ *](.*)$")]
    private static partial Regex GnuHash();

    /// <summary>ps's lstart, "Sun Oct 11 10:00:00 2026", as "2026-10-11 10:00:00".</summary>
    internal static string? LStart(string value) =>
        DateTime.TryParseExact(Regex.Replace(value, @"\s+", " "), "ddd MMM d HH:mm:ss yyyy",
                               CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)
            ? t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
            : null;

    // --- network -----------------------------------------------------------------------------

    private static CsvFile Network(Context c)
    {
        var csv = c.Csv("LinuxLiveResponse_Network.csv",
            "Protocol", "State", "LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "PIDs", "Processes", "SourceFile");

        if (c.Find("network/ss_-anp.txt", "network/ss_-tanp.txt") is { } ss)
        {
            c.Parsed[ss] = csv.FileName;
            var lines = File.ReadLines(ss).ToList();
            var withNetid = lines.FirstOrDefault()?.StartsWith("Netid", StringComparison.Ordinal) == true;
            var unread = 0;
            foreach (var line in lines.Skip(1))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var (t, rest) = Fields(line, withNetid ? 6 : 5);
                if (t is null) { unread++; continue; }
                var netid = withNetid ? t[0] : "tcp";
                var o = withNetid ? 1 : 0;
                // Unix, netlink and packet sockets have no addresses to read; they are left out.
                if (!InetNetid().IsMatch(netid)) continue;
                var (la, lp) = HostPort(t[o + 3]);
                var (ra, rp) = HostPort(t[o + 4]);
                var owners = SsUsers().Matches(rest).Select(m => (Name: m.Groups[1].Value, Pid: m.Groups[2].Value)).ToList();
                csv.Write(netid, t[o], la, lp, ra, rp,
                          string.Join(", ", owners.Select(x => x.Pid).Distinct()),
                          string.Join(", ", owners.Select(x => x.Name).Distinct()), c.Source(ss));
            }
            c.Unread(ss, unread, "ss");
            return csv;
        }

        if (c.Find("network/netstat_-anp.txt", "network/netstat_-lpeanut.txt") is { } netstat)
        {
            c.Parsed[netstat] = csv.FileName;
            foreach (var line in File.ReadLines(netstat))
            {
                if (!NetstatProto().IsMatch(line)) continue;
                var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (t.Length < 6) continue;
                var hasState = t.Length > 6 || StateWord().IsMatch(t[5]);
                var state = hasState ? t[5] : "";
                var owner = t.Length > (hasState ? 6 : 5) ? string.Join(' ', t[(hasState ? 6 : 5)..]) : "";
                // -lpeanut adds User and Inode before PID/Program.
                if (netstat.EndsWith("lpeanut.txt", StringComparison.Ordinal) && hasState && t.Length >= 9)
                    owner = string.Join(' ', t[8..]);
                var slash = owner.IndexOf('/');
                var (la, lp) = HostPort(t[3]);
                var (ra, rp) = HostPort(t[4]);
                csv.Write(t[0], state, la, lp, ra, rp, slash > 0 ? owner[..slash] : "",
                          slash > 0 ? owner[(slash + 1)..] : "", c.Source(netstat));
            }
        }
        return csv;
    }

    [GeneratedRegex(@"^(tcp|udp|raw|sctp|icmp6|tcp6|udp6|raw6|udplite|mptcp)")]
    private static partial Regex InetNetid();

    [GeneratedRegex(@"\(""([^""]*)"",pid=(\d+)")]
    private static partial Regex SsUsers();

    [GeneratedRegex(@"^(tcp|udp|raw)6?\s")]
    private static partial Regex NetstatProto();

    [GeneratedRegex(@"^[A-Z][A-Z0-9_]+$")]
    private static partial Regex StateWord();

    /// <summary>"0.0.0.0:22", "[::]:22", "*:*", "127.0.0.53%lo:53" into address and port.</summary>
    internal static (string Address, string Port) HostPort(string value)
    {
        var colon = value.LastIndexOf(':');
        if (colon < 0) return (value, "");
        var host = value[..colon];
        if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];
        return (host, value[(colon + 1)..]);
    }

    private static CsvFile Interfaces(Context c)
    {
        var csv = c.Csv("LinuxLiveResponse_Interfaces.csv", "Interface", "State", "Flags", "MAC", "Family", "Address", "Scope", "SourceFile");
        if (c.Find("network/ip_addr_show.txt") is not { } path) return csv;
        c.Parsed[path] = csv.FileName;

        string name = "", state = "", flags = "", mac = "";
        var addresses = 0;
        void Flush()
        {
            // An interface with no address still exists and is listed once.
            if (name.Length > 0 && addresses == 0) csv.Write(name, state, flags, mac, "", "", "", c.Source(path));
        }

        foreach (var line in File.ReadLines(path))
        {
            var head = IpLinkHead().Match(line);
            if (head.Success)
            {
                Flush();
                (name, flags, addresses, mac) = (head.Groups[1].Value, head.Groups[2].Value, 0, "");
                var s = Regex.Match(line, @"\sstate (\S+)");
                state = s.Success ? s.Groups[1].Value : "";
                continue;
            }
            var t = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (t.Length < 2) continue;
            if (t[0].StartsWith("link/", StringComparison.Ordinal)) { mac = t[1]; continue; }
            if (t[0] is "inet" or "inet6")
            {
                var scope = Array.IndexOf(t, "scope") is var i and >= 0 && i + 1 < t.Length ? t[i + 1] : "";
                csv.Write(name, state, flags, mac, t[0] == "inet" ? "IPv4" : "IPv6", t[1], scope, c.Source(path));
                addresses++;
            }
        }
        Flush();
        return csv;
    }

    [GeneratedRegex(@"^\d+:\s+([^:\s@]+)(?:@\S+)?:\s+<([^>]*)>")]
    private static partial Regex IpLinkHead();

    private static CsvFile Routes(Context c)
    {
        var csv = c.Csv("LinuxLiveResponse_Routes.csv", "Destination", "Gateway", "Interface", "Source", "Route", "SourceFile");
        if (c.Find("network/ip_route_show.txt") is not { } path) return csv;
        c.Parsed[path] = csv.FileName;
        foreach (var line in File.ReadLines(path).Where(l => !string.IsNullOrWhiteSpace(l)))
        {
            var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            csv.Write(t[0], After(t, "via"), After(t, "dev"), After(t, "src"), line.Trim(), c.Source(path));
        }
        return csv;
    }

    private static CsvFile Neighbours(Context c)
    {
        var csv = c.Csv("LinuxLiveResponse_Neighbours.csv", "Address", "MAC", "Interface", "State", "SourceFile");
        if (c.Find("network/ip_neighbor_show.txt") is { } ip)
        {
            c.Parsed[ip] = csv.FileName;
            foreach (var line in File.ReadLines(ip).Where(l => !string.IsNullOrWhiteSpace(l)))
            {
                var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                csv.Write(t[0], After(t, "lladdr"), After(t, "dev"), t[^1], c.Source(ip));
            }
            return csv;
        }

        if (c.Find("network/arp_-a.txt") is { } arp)
        {
            c.Parsed[arp] = csv.FileName;
            foreach (var line in File.ReadLines(arp))
            {
                // ? (10.0.0.1) at 52:54:00:12:34:56 [ether] on eth0
                var m = Regex.Match(line, @"\(([^)]+)\) at (\S+)(?: \[\w+\])?(?: on (\S+))?");
                if (m.Success) csv.Write(m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value, "", c.Source(arp));
            }
        }
        return csv;
    }

    private static string After(string[] tokens, string word)
    {
        var i = Array.IndexOf(tokens, word);
        return i >= 0 && i + 1 < tokens.Length ? tokens[i + 1] : "";
    }

    // --- open files --------------------------------------------------------------------------

    private static CsvFile OpenFiles(Context c, CancellationToken cancellationToken)
    {
        var csv = c.Csv("LinuxLiveResponse_OpenFiles.csv", "Command", "PID", "User", "FD", "Type", "Name", "Deleted", "SourceFile");
        if (c.Find("process/lsof_-nPl.txt", "network/lsof_-nPl.txt") is not { } path) return csv;
        c.Parsed[path] = csv.FileName;

        using var lines = File.ReadLines(path).GetEnumerator();
        if (!lines.MoveNext()) return csv;
        var header = Columns(lines.Current);
        var nameAt = header.FindIndex(h => h.Label == "NAME");
        if (nameAt < 0 || header[0].Label != "COMMAND")
        {
            c.Errors.WriteLine($"{c.Source(path)}: no lsof header line - not parsed");
            return csv;
        }

        var unread = 0;
        while (lines.MoveNext())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = lines.Current;
            if (string.IsNullOrWhiteSpace(line)) continue;

            // lsof pads its columns but leaves optional ones (TID, DEVICE, SIZE/OFF) blank, so
            // fields are placed by where they sit under the header, not by counting them.
            var nameStart = header[nameAt].Start;
            var name = line.Length > nameStart ? line[nameStart..].TrimEnd() : "";
            var cells = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (text, start, end) in Tokens(line.Length > nameStart ? line[..nameStart] : line))
            {
                var column = header.Take(nameAt).OrderByDescending(h => Overlap(h.Start, h.End, start, end))
                                   .ThenBy(h => Distance(h.Start, h.End, start, end)).First();
                cells[column.Label] = cells.TryGetValue(column.Label, out var existing) ? existing + " " + text : text;
            }

            var pid = cells.GetValueOrDefault("PID", "");
            if (pid.Length == 0 || !pid.All(char.IsAsciiDigit)) { unread++; continue; }
            // FD 'DEL' is a deleted file still mapped into the process.
            var deleted = name.EndsWith("(deleted)", StringComparison.Ordinal) || cells.GetValueOrDefault("FD") == "DEL";
            csv.Write(cells.GetValueOrDefault("COMMAND", ""), pid, cells.GetValueOrDefault("USER", ""),
                      cells.GetValueOrDefault("FD", ""), cells.GetValueOrDefault("TYPE", ""), name,
                      deleted ? "yes" : "", c.Source(path));
        }
        c.Unread(path, unread, "lsof");
        return csv;
    }

    private sealed record Column(string Label, int Start, int End);

    private static List<Column> Columns(string header) =>
        Tokens(header).Select(t => new Column(t.Text, t.Start, t.End)).ToList();

    private static IEnumerable<(string Text, int Start, int End)> Tokens(string line)
    {
        var i = 0;
        while (i < line.Length)
        {
            while (i < line.Length && line[i] == ' ') i++;
            var start = i;
            while (i < line.Length && line[i] != ' ') i++;
            if (i > start) yield return (line[start..i], start, i);
        }
    }

    private static int Overlap(int a0, int a1, int b0, int b1) => Math.Max(0, Math.Min(a1, b1) - Math.Max(a0, b0));

    private static int Distance(int a0, int a1, int b0, int b1) => b1 <= a0 ? a0 - b1 : b0 >= a1 ? b0 - a1 : 0;

    // --- kernel modules ----------------------------------------------------------------------

    private static CsvFile KernelModules(Context c)
    {
        var csv = c.Csv("LinuxLiveResponse_KernelModules.csv", "Module", "Size", "UseCount", "UsedBy", "State", "TaintFlags", "TaintMeaning", "SourceFile");

        if (c.Find("process/proc/modules.txt") is { } modules)
        {
            // name size refcount deps state address [(taint)]
            c.Parsed[modules] = csv.FileName;
            foreach (var line in File.ReadLines(modules).Where(l => !string.IsNullOrWhiteSpace(l)))
            {
                var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (t.Length < 5) continue;
                var taint = t.Length > 6 ? t[6].Trim('(', ')') : "";
                csv.Write(t[0], t[1], t[2], t[3] == "-" ? "" : t[3].TrimEnd(','), t[4], taint, TaintMeaning(taint), c.Source(modules));
            }
            return csv;
        }

        if (c.Find("system/lsmod.txt") is { } lsmod)
        {
            c.Parsed[lsmod] = csv.FileName;
            foreach (var line in File.ReadLines(lsmod).Skip(1).Where(l => !string.IsNullOrWhiteSpace(l)))
            {
                var t = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (t.Length < 3) continue;
                csv.Write(t[0], t[1], t[2], t.Length > 3 ? t[3] : "", "", "", "", c.Source(lsmod));
            }
        }
        return csv;
    }

    /// <summary>The kernel's per-module taint letters. Out-of-tree and unsigned are common for
    /// legitimate drivers (VirtualBox, NVIDIA), so they are explained, not flagged.</summary>
    internal static string TaintMeaning(string flags) => string.Join("; ", flags.Select(f => f switch
    {
        'P' => "proprietary licence",
        'O' => "out-of-tree (not built with the kernel)",
        'E' => "unsigned",
        'F' => "force-loaded",
        'C' => "staging driver",
        'X' => "auxiliary (SUSE)",
        'T' => "built with struct randomisation plugin",
        _ => f.ToString()
    }));

    // --- index -------------------------------------------------------------------------------

    private static CsvFile Index(Context c)
    {
        var csv = c.Csv("LinuxLiveResponse_Index.csv", "Category", "File", "Bytes", "Lines", "ParsedInto", "SourceFile");
        foreach (var file in new DirectoryInfo(c.Live).EnumerateFiles("*", SearchOption.AllDirectories)
                     .OrderBy(f => f.FullName, StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(c.Live, file.FullName).Replace('\\', '/');
            var category = relative.Contains('/') ? relative[..relative.IndexOf('/')] : "";
            // Counting lines of a dumped process image would be meaningless; text only.
            var lines = file.Extension == ".txt" && file.Length < 256L * 1024 * 1024
                ? File.ReadLines(file.FullName).LongCount().ToString(CultureInfo.InvariantCulture)
                : "";
            csv.Write(category, relative, file.Length.ToString(CultureInfo.InvariantCulture), lines,
                      c.Parsed.GetValueOrDefault(file.FullName, ""), c.Source(file.FullName));
        }
        return csv;
    }

    // --- helpers -----------------------------------------------------------------------------

    /// <summary>
    /// The first <paramref name="count"/> whitespace-separated fields, and the rest of the line
    /// exactly as written (a command line keeps its own spacing). Null when the line is shorter.
    /// </summary>
    internal static (string[]? Fields, string Remainder) Fields(string line, int count)
    {
        var fields = new string[count];
        var i = 0;
        for (var f = 0; f < count; f++)
        {
            while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
            var start = i;
            while (i < line.Length && !char.IsWhiteSpace(line[i])) i++;
            if (i == start) return (null, "");
            fields[f] = line[start..i];
        }
        while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
        return (fields, line[i..]);
    }
}

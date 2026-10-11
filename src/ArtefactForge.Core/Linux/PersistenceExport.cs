using System.Globalization;
using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

/// <summary>
/// The LinuxPersistence module: the places on a Linux system where something can be made to run,
/// or be let in, that cron and systemd (their own modules) do not cover.
///
///   LinuxPersistence_Locations.csv  every file found at a persistence location, with its
///                                   modification time - the quickest way to spot the one changed
///                                   recently
///   LinuxPersistence_Entries.csv    the lines that do something: every line of files that only
///                                   exist to run or load something (ld.so.preload, rc.local,
///                                   ~/.ssh/rc), and the lines worth a look in the large shared
///                                   ones (shell startup files, PAM, sshd_config, udev rules)
///
/// Locations: ld.so.preload and LD_PRELOAD in /etc/environment; rc.local; system-wide and per-user
/// shell startup files; MOTD scripts run at every SSH login; XDG autostart; user systemd units;
/// sshd_config and ~/.ssh/rc; PAM; kernel modules loaded at boot and modprobe install commands;
/// udev RUN rules; APT hooks; SysV init scripts.
///
/// The Review column says why a line deserves a look. It is a pointer, not a verdict: an
/// administrator's own MOTD script trips the same check as an attacker's.
/// </summary>
public static partial class PersistenceExport
{
    public static int Run(string root, string outputDirectory, TextWriter log, TextWriter errors, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(Path.Combine(root, "etc")) && !Directory.Exists(Path.Combine(root, "home")))
        {
            log.WriteLine($"No etc or home folder under {root}");
            return 0;
        }

        Directory.CreateDirectory(outputDirectory);
        using var locations = new CsvFile(Path.Combine(outputDirectory, "LinuxPersistence_Locations.csv"),
            "Mechanism", "Path", "ModifiedUtc", "Size", "ActiveLines", "Review", "SourceFile");
        using var entries = new CsvFile(Path.Combine(outputDirectory, "LinuxPersistence_Entries.csv"),
            "Mechanism", "Path", "Line", "Entry", "Review", "ModifiedUtc", "SourceFile");
        var scan = new Scan(root, locations, entries);

        // Files whose every line runs or loads something.
        scan.Files("Preloaded library (ld.so.preload)", ["etc/ld.so.preload"], EveryLine("library loaded into every process"));
        scan.Files("Boot script (rc.local)", ["etc/rc.local", "etc/rc.d/rc.local"],
                   line => line.Trim() == "exit 0" ? null : "runs at boot");
        scan.Files("Kernel module loaded at boot", ["etc/modules", "etc/modules-load.d/*.conf", "usr/lib/modules-load.d/*.conf"],
                   _ => "");

        // Large shared files: only lines that look like something were added.
        scan.Files("Environment", ["etc/environment"], line => Preload().IsMatch(line) ? "sets a preload or library path" : null);
        scan.Files("Shell startup (system)",
                   ["etc/profile", "etc/profile.d/*", "etc/bash.bashrc", "etc/bashrc", "etc/zsh/*", "etc/zshrc", "etc/zprofile", "etc/csh.cshrc"],
                   Suspicious);
        scan.Files("Login message script (MOTD, runs at every SSH login)", ["etc/update-motd.d/*"], Suspicious);
        scan.Files("Autostart (XDG, desktop sessions)", ["etc/xdg/autostart/*.desktop"], Autostart);
        scan.Files("SSH server configuration", ["etc/ssh/sshd_config", "etc/ssh/sshd_config.d/*.conf"], SshdConfig);
        scan.Files("SSH login script (sshrc)", ["etc/ssh/sshrc"], EveryLine("runs at every SSH login"));
        scan.Files("PAM", ["etc/pam.d/*"], Pam);
        scan.Files("Module install command (modprobe)", ["etc/modprobe.d/*.conf", "usr/lib/modprobe.d/*.conf"],
                   line => InstallCommand().IsMatch(line) ? "runs a command when the module is loaded" : null);
        scan.Files("Device event rule (udev)", ["etc/udev/rules.d/*.rules"],
                   line => line.Contains("RUN", StringComparison.Ordinal) ? "runs a program on a device event" : null);
        scan.Files("Package manager hook (APT)", ["etc/apt/apt.conf.d/*"],
                   line => AptHook().IsMatch(line) ? "runs a command around every apt operation" : null);
        scan.Files("Init script (SysV)", ["etc/init.d/*", "etc/rc.d/init.d/*"], _ => null);

        foreach (var (user, home) in Homes(root))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var prefix = Path.GetRelativePath(root, home).Replace('\\', '/') + "/";
            scan.Files($"Shell startup ({user})",
                       [.. new[] { ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc",
                                   ".zprofile", ".zlogin", ".zshenv", ".cshrc", ".tcshrc", ".config/fish/config.fish" }
                           .Select(f => prefix + f)],
                       Suspicious);
            scan.Files($"SSH login script ({user})", [prefix + ".ssh/rc"], EveryLine("runs at every SSH login by this user"));
            scan.Files($"Autostart ({user})", [prefix + ".config/autostart/*.desktop"], Autostart);
            scan.Files($"User systemd unit ({user})", [prefix + ".config/systemd/user/*.service", prefix + ".config/systemd/user/*.timer"],
                       line => line.TrimStart().StartsWith("Exec", StringComparison.Ordinal) ? "runs when this user logs in or on its timer" : null);
        }

        foreach (var csv in new[] { locations, entries })
            if (csv.Rows > 0) log.WriteLine($"  {csv.FileName,-34} {csv.Rows} row(s)");
        if (locations.Rows == 0) log.WriteLine("No persistence locations found");
        return 0;
    }

    /// <summary>Why a line deserves a look; null for a line to leave out, "" to list without comment.</summary>
    private delegate string? Check(string line);

    private sealed class Scan(string root, CsvFile locations, CsvFile entries)
    {
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

        public void Files(string mechanism, IEnumerable<string> patterns, Check check)
        {
            foreach (var file in patterns.SelectMany(Expand))
            {
                if (!_seen.Add(file.FullName)) continue;
                var relative = Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
                var modified = file.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

                var active = 0;
                var flagged = new List<string>();
                var number = 0;
                foreach (var raw in ReadLines(file))
                {
                    number++;
                    var line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
                    active++;
                    var review = check(line);
                    if (review is null) continue;
                    entries.Write(mechanism, relative, number.ToString(CultureInfo.InvariantCulture), line, review, modified, relative);
                    if (review.Length > 0) flagged.Add(review);
                }
                locations.Write(mechanism, relative, modified, file.Length.ToString(CultureInfo.InvariantCulture),
                                active.ToString(CultureInfo.InvariantCulture),
                                string.Join("; ", flagged.Distinct()), relative);
            }
        }

        private IEnumerable<FileInfo> Expand(string pattern)
        {
            var parts = pattern.Split('/');
            var dir = new DirectoryInfo(Path.Combine([root, .. parts[..^1]]));
            if (!dir.Exists) return [];
            var name = parts[^1];
            if (!name.Contains('*'))
            {
                var file = new FileInfo(Path.Combine(dir.FullName, name));
                return file.Exists ? [file] : [];
            }
            return dir.EnumerateFiles(name).OrderBy(f => f.Name, StringComparer.Ordinal);
        }

        private static IEnumerable<string> ReadLines(FileInfo file)
        {
            // A binary dropped where a script belongs is still listed as a location; its bytes are not lines.
            if (file.Length > 4 * 1024 * 1024) return [];
            try { return File.ReadAllLines(file.FullName); }
            catch (IOException) { return []; }
        }
    }

    private static Check EveryLine(string reason) => _ => reason;

    /// <summary>Every reason a line looks added, or null for an ordinary one.</summary>
    private static string? Suspicious(string line)
    {
        var reasons = new List<string>();
        if (Preload().IsMatch(line)) reasons.Add("sets a preload or library path");
        if (Download().IsMatch(line)) reasons.Add("downloads or opens a network connection");
        if (Encoded().IsMatch(line)) reasons.Add("decodes or runs inline code");
        if (TempPath().IsMatch(line)) reasons.Add("refers to a temporary or shared-memory folder");
        // alias ls='ls --color=auto' is every distribution's default; alias sudo='/tmp/x' is not.
        var alias = AliasOver().Match(line);
        if (alias.Success && alias.Groups[2].Value.Trim('\'', '"').Split(' ')[0] != alias.Groups[1].Value)
            reasons.Add("redefines a command an administrator relies on");
        if (line.Contains("PROMPT_COMMAND", StringComparison.Ordinal)) reasons.Add("runs a command before every prompt");
        if (line.Contains("trap ", StringComparison.Ordinal) && line.Contains("DEBUG", StringComparison.Ordinal))
            reasons.Add("runs a command before every command");
        return reasons.Count > 0 ? string.Join("; ", reasons) : null;
    }

    private static string? Autostart(string line) =>
        line.StartsWith("Exec=", StringComparison.Ordinal) ? (Suspicious(line[5..]) ?? "") : null;

    private static string? SshdConfig(string line)
    {
        var parts = line.Split((char[])[' ', '\t'], 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return null;
        var (key, value) = (parts[0], parts[1].Trim());
        return key.ToLowerInvariant() switch
        {
            "permitrootlogin" => value.Equals("yes", StringComparison.OrdinalIgnoreCase) ? "root may log in with a password" : "",
            "permitemptypasswords" => value.Equals("yes", StringComparison.OrdinalIgnoreCase) ? "accounts with no password may log in" : "",
            "authorizedkeysfile" => value.Split(' ').Any(v => v is not (".ssh/authorized_keys" or ".ssh/authorized_keys2" or "%h/.ssh/authorized_keys"))
                ? "keys read from a non-default file" : "",
            "authorizedkeyscommand" => "keys supplied by a program",
            "forcecommand" or "match" => "",
            "passwordauthentication" or "pubkeyauthentication" or "port" or "listenaddress" or "allowusers"
                or "allowgroups" or "permittunnel" or "gatewayports" or "subsystem" or "include" => "",
            _ => null
        };
    }

    /// <summary>
    /// PAM lines are listed when they load a module outside the standard set, run a program
    /// (pam_exec), or let anyone through authentication (pam_permit as sufficient).
    /// </summary>
    private static string? Pam(string line)
    {
        var fields = line.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 3 || fields[0].StartsWith('@')) return null;
        var type = fields[0].TrimStart('-');
        var control = fields[1].StartsWith('[') ? "" : fields[1];
        var module = fields.FirstOrDefault(f => f.Contains(".so", StringComparison.Ordinal));
        if (module is null) return null;

        if (module.StartsWith('/') && !StandardPamDir().IsMatch(module)) return "module loaded from outside the PAM folders";
        var name = Path.GetFileName(module);
        if (name == "pam_exec.so") return "runs a program during authentication or session";
        if (name == "pam_permit.so" && type == "auth" && control == "sufficient") return "authentication succeeds for anyone";
        return StandardPam.Contains(name) ? null : "module not in the standard set";
    }

    private static readonly HashSet<string> StandardPam = new(StringComparer.Ordinal)
    {
        "pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_env.so", "pam_limits.so", "pam_systemd.so",
        "pam_loginuid.so", "pam_keyinit.so", "pam_selinux.so", "pam_namespace.so", "pam_nologin.so",
        "pam_securetty.so", "pam_motd.so", "pam_mail.so", "pam_lastlog.so", "pam_lastlog2.so", "pam_umask.so",
        "pam_succeed_if.so", "pam_faillock.so", "pam_pwquality.so", "pam_cracklib.so", "pam_rootok.so",
        "pam_wheel.so", "pam_xauth.so", "pam_sss.so", "pam_systemd_home.so", "pam_gnome_keyring.so",
        "pam_kwallet5.so", "pam_kwallet.so", "pam_fprintd.so", "pam_cap.so", "pam_access.so", "pam_time.so",
        "pam_tally2.so", "pam_shells.so", "pam_faildelay.so", "pam_localuser.so", "pam_listfile.so",
        "pam_sepermit.so", "pam_console.so", "pam_mkhomedir.so", "pam_tty_audit.so", "pam_pwhistory.so",
        "pam_timestamp.so", "pam_ecryptfs.so", "pam_winbind.so", "pam_krb5.so", "pam_ldap.so",
        "pam_google_authenticator.so", "pam_oddjob_mkhomedir.so", "pam_usertype.so", "pam_extrausers.so",
        "pam_gdm.so", "pam_userdb.so", "pam_echo.so", "pam_warn.so", "pam_issue.so", "pam_ftp.so",
        "pam_group.so", "pam_mount.so", "pam_u2f.so", "pam_yubico.so", "pam_systemd_loadkey.so",
        "pam_unix2.so", "pam_sss_gss.so", "pam_pwdfile.so", "pam_rhosts.so", "pam_fscrypt.so",
        "pam_gnome_keyring.so", "pam_cgfs.so", "pam_lsass.so", "pam_mate_keyring.so", "pam_snapper.so"
    };

    [GeneratedRegex(@"^/(usr/)?lib(64|32)?/(x86_64-linux-gnu/|aarch64-linux-gnu/|i386-linux-gnu/)?security/")]
    private static partial Regex StandardPamDir();

    [GeneratedRegex(@"\bLD_(PRELOAD|LIBRARY_PATH|AUDIT)\b")]
    private static partial Regex Preload();

    [GeneratedRegex(@"/dev/(tcp|udp)/|\b(curl|wget|nc|ncat|netcat|socat|telnet)\b|openssl s_client")]
    private static partial Regex Download();

    [GeneratedRegex(@"base64\s+(-d|--decode)|\bxxd -r\b|\b(python[0-9.]*|perl|ruby|php)\s+-[ce]\b|\bmkfifo\b")]
    private static partial Regex Encoded();

    [GeneratedRegex(@"(^|[\s=:""'])/(tmp|var/tmp|dev/shm)/")]
    private static partial Regex TempPath();

    [GeneratedRegex(@"^\s*alias\s+(sudo|su|ssh|ls|ps|netstat|ss|lsof|top|passwd|cd)=(.*)$")]
    private static partial Regex AliasOver();

    [GeneratedRegex(@"^\s*install\s")]
    private static partial Regex InstallCommand();

    [GeneratedRegex(@"(Pre|Post)-Invoke|Update::Post-Invoke|APT::Update::Pre-Invoke|DPkg::Pre-Install-Pkgs")]
    private static partial Regex AptHook();

    /// <summary>Each user's home, from the collected tree: home/* and root.</summary>
    private static IEnumerable<(string User, string Home)> Homes(string root)
    {
        var rootHome = Path.Combine(root, "root");
        if (Directory.Exists(rootHome)) yield return ("root", rootHome);
        var home = new DirectoryInfo(Path.Combine(root, "home"));
        if (!home.Exists) yield break;
        foreach (var dir in home.EnumerateDirectories().OrderBy(d => d.Name, StringComparer.Ordinal))
            yield return (dir.Name, dir.FullName);
    }
}

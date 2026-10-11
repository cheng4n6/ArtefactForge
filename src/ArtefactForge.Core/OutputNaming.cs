using System.Text.RegularExpressions;

namespace ArtefactForge.Core;

/// <summary>
/// Builds the final output filename. Category folders are shared by every module, so the name
/// alone has to say which tool produced the file and, for per-user artefacts, whose it is.
/// Convention: [User_]Tool_Detail.ext - user first so one profile's files group together.
/// </summary>
public static partial class OutputNaming
{
    /// <summary>
    /// Leading tool timestamps such as '20260819002514_' (yyyyMMddHHmmss, most EZ Tools) or
    /// '20260819002514123456_' (yyyyMMddHHmmssffffff, SQLECmd). The run time lives in the manifest.
    /// </summary>
    [GeneratedRegex(@"^\d{8,20}_")]
    private static partial Regex LeadingTimestamp();

    public static string Build(string originalFileName, string outputName, string? user)
    {
        var extension = Path.GetExtension(originalFileName);
        var stem = Path.GetFileNameWithoutExtension(originalFileName);

        stem = LeadingTimestamp().Replace(stem, "");

        // Some tools embed the user themselves (WxTCmd writes '<ts>_User_Activity.csv').
        // Strip it so the prefix is not applied twice.
        if (user is not null && stem.StartsWith(user + "_", StringComparison.OrdinalIgnoreCase))
            stem = stem[(user.Length + 1)..];

        // Strip separators left behind by the two steps above, so a filename that was nothing but
        // a timestamp and a username does not come out as 'Tool_.csv'.
        stem = stem.Trim('_');

        // 'Contains' rather than 'StartsWith': SBECmd writes '!SBECmd_Messages.txt', and
        // SrumECmd writes 'SrumECmd_NetworkUsages_Output.csv'. Both already identify the tool.
        if (stem.Length == 0) stem = outputName;
        else if (!stem.Contains(outputName, StringComparison.OrdinalIgnoreCase))
            stem = outputName + "_" + stem;

        return user is null ? stem + extension : user + "_" + stem + extension;
    }

    /// <summary>Appends _2, _3 ... when a name is already taken in the destination folder.</summary>
    public static string Deduplicate(string directory, string fileName)
    {
        if (!File.Exists(Path.Combine(directory, fileName))) return fileName;

        var stem = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        for (var n = 2; ; n++)
        {
            var candidate = $"{stem}_{n}{extension}";
            if (!File.Exists(Path.Combine(directory, candidate))) return candidate;
        }
    }
}

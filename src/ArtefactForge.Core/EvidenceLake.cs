namespace ArtefactForge.Core;

/// <summary>
/// The evidence lake: one queryable database built from every host's output, in
/// &lt;Case&gt;\_Lake\ (a "_" folder, so nothing treats it as a host). It reads each host's
/// outputs.json (<see cref="HostOutputs"/>) and never ArtefactForge's internals. It is an add-on
/// that only builds when the analyst asks for it, and this build does not include it, so asking
/// says so instead of passing in silence.
/// </summary>
public static class EvidenceLake
{
    public const string FolderName = "_Lake";
    public const string ModuleName = "EvidenceLake";
    public const string NotInstalled = "The evidence lake add-on is not installed in this build";

    /// <summary>False until the add-on ships; the front ends check it before offering the lake.</summary>
    public static bool IsInstalled => false;

    /// <summary>
    /// Builds the lake for a case, after a run or on its own. Without the add-on the result says
    /// it is not installed, and is marked for review because the analyst asked for a lake and has
    /// none.
    /// </summary>
    public static WorkResult Build(string caseDirectory) => new()
    {
        Collection = Path.GetFileName(Path.TrimEndingDirectorySeparator(caseDirectory)),
        Module = ModuleName,
        Category = "Lake",
        Status = WorkStatus.ToolMissing,
        Reason = NotInstalled,
        Destination = Path.Combine(caseDirectory, FolderName),
        Started = DateTimeOffset.Now
    };
}

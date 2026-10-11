namespace ArtefactForge.Core;

/// <summary>
/// Validates a host name supplied by the analyst. The name becomes a folder under the case
/// directory, so anything that cannot be a folder has to be refused here rather than surfacing as
/// an IO error partway through a run.
/// </summary>
public static class CollectionNaming
{
    /// <summary>Long enough for any real hostname, short enough to keep paths sane.</summary>
    public const int MaxLength = 64;

    // Reserved on Windows regardless of extension: a folder called CON cannot be created.
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    /// <summary>
    /// Returns true and the trimmed name when usable. On false, <paramref name="error"/> says what
    /// is wrong in terms the analyst can act on.
    /// </summary>
    public static bool TryValidate(string? raw, out string name, out string? error)
    {
        name = (raw ?? string.Empty).Trim();

        if (name.Length == 0)
        {
            error = "a name is required";
            return false;
        }

        if (name.Length > MaxLength)
        {
            error = $"longer than {MaxLength} characters";
            return false;
        }

        var invalid = name.Where(c => Path.GetInvalidFileNameChars().Contains(c)).Distinct().ToArray();
        if (invalid.Length > 0)
        {
            error = "cannot contain " + string.Join(" ", invalid.Select(c => char.IsControl(c) ? "control characters" : $"'{c}'"));
            return false;
        }

        // Windows silently strips these from the end of a folder name, so a name that differs only
        // by a trailing dot or space would collide with another.
        if (name.EndsWith('.') || name != name.TrimEnd())
        {
            error = "cannot end with a dot or a space";
            return false;
        }

        if (Reserved.Contains(name))
        {
            error = $"'{name}' is a reserved Windows device name";
            return false;
        }

        error = null;
        return true;
    }
}

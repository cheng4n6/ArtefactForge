namespace ArtefactForge.Core;

/// <summary>
/// Turns a module's declared options plus the analyst's overrides into the command-line fragment
/// that replaces '%options%'.
///
/// Only declared options can be set. That is the point: the module author decides what is safe to
/// vary, so a run stays reproducible and a typo cannot quietly produce a command that parses
/// nothing. The manifest records the finished command line either way.
/// </summary>
public static class ModuleOptions
{
    /// <summary>Values in effect for a module: declared defaults with overrides applied.</summary>
    public static IReadOnlyDictionary<string, string> Effective(
        ModuleDefinition module, IReadOnlyDictionary<string, string>? overrides = null)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var option in module.Options) values[option.Name] = option.Default;

        if (overrides is null) return values;

        foreach (var (name, value) in overrides)
            if (values.ContainsKey(name))
                values[name] = value;

        return values;
    }

    /// <summary>
    /// The fragment for '%options%'. Options appear in declaration order, so the resulting command
    /// line is stable and diffable between runs.
    /// </summary>
    public static string Expand(ModuleDefinition module, IReadOnlyDictionary<string, string>? overrides = null)
    {
        var values = Effective(module, overrides);
        var parts = new List<string>();

        foreach (var option in module.Options)
        {
            // An option the engine reads itself, such as a Split's number of parts.
            if (option.Expand.Length == 0) continue;
            var value = values[option.Name];

            if (option.Kind == OptionKind.Flag)
            {
                if (IsOn(value)) parts.Add(option.Expand);
                continue;
            }

            // An empty Choice or Text contributes nothing, which is how an option is turned off.
            if (string.IsNullOrWhiteSpace(value)) continue;
            parts.Add(option.Expand.Replace("%value%", value.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        return string.Join(" ", parts);
    }

    /// <summary>
    /// Checks an override before a run starts. Returns false with a reason the analyst can act on,
    /// rather than letting an unknown name be silently ignored or a bad value reach the tool.
    /// </summary>
    public static bool TryValidate(ModuleDefinition module, string name, string value, out string? error)
    {
        var option = module.Options.FirstOrDefault(o => string.Equals(o.Name, name, StringComparison.OrdinalIgnoreCase));
        if (option is null)
        {
            var known = module.Options.Count == 0
                ? $"{module.Name} has no options"
                : "known options: " + string.Join(", ", module.Options.Select(o => o.Name));
            error = $"{module.Name} has no option '{name}' ({known})";
            return false;
        }

        switch (option.Kind)
        {
            case OptionKind.Flag when !IsBoolean(value):
                error = $"{module.Name}.{option.Name} is a flag; use true or false, not '{value}'";
                return false;

            case OptionKind.Choice when value.Length > 0
                                        && !option.Choices.Contains(value, StringComparer.OrdinalIgnoreCase):
                error = $"{module.Name}.{option.Name} must be one of: {string.Join(", ", option.Choices)}";
                return false;
        }

        error = null;
        return true;
    }

    private static bool IsOn(string value) =>
        value.Equals("true", StringComparison.OrdinalIgnoreCase)
        || value.Equals("yes", StringComparison.OrdinalIgnoreCase)
        || value == "1";

    private static bool IsBoolean(string value) =>
        IsOn(value)
        || value.Equals("false", StringComparison.OrdinalIgnoreCase)
        || value.Equals("no", StringComparison.OrdinalIgnoreCase)
        || value == "0";
}

namespace ArtefactForge.Core;

public static class ModuleLoader
{
    public static readonly string[] Extensions = ["*.forge", "*.mkape"];

    /// <summary>
    /// Loads every module beneath <paramref name="directory"/>. A file that fails to parse or
    /// validate is collected as an error rather than thrown, so one bad module never stops a run.
    /// </summary>
    public static LoadResult<ModuleDefinition> LoadDirectory(string directory)
    {
        var result = new LoadResult<ModuleDefinition>();
        if (!Directory.Exists(directory))
        {
            result.Errors.Add(new LoadError(directory, "Module directory not found."));
            return result;
        }

        var files = Extensions
            .SelectMany(ext => Directory.EnumerateFiles(directory, ext, SearchOption.AllDirectories))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            try { result.Items.Add(LoadFile(file)); }
            catch (Exception ex) { result.Errors.Add(new LoadError(file, ex.Message)); }
        }
        return result;
    }

    public static ModuleDefinition LoadFile(string path)
    {
        var dto = Yaml.Deserializer.Deserialize<ModuleDto>(File.ReadAllText(path))
                  ?? throw new FormatException("File is empty or not valid YAML.");

        if (dto.Processors is null || dto.Processors.Count == 0)
            throw new FormatException("No Processors defined - a module must run at least one tool.");

        var processors = ReadProcessors(dto.Processors, "Processor");
        var prepare = ReadProcessors(dto.Prepare, "Prepare step");
        var options = ReadOptions(dto.Options);

        return new ModuleDefinition
        {
            Description  = dto.Description ?? Path.GetFileNameWithoutExtension(path),
            Category     = string.IsNullOrWhiteSpace(dto.Category) ? "Uncategorised" : dto.Category.Trim(),
            Author       = dto.Author,
            Version      = dto.Version,
            Id           = dto.Id,
            ExportFormat = dto.ExportFormat,
            FileMask     = dto.FileMask,
            Processors   = processors,
            Prepare      = prepare,
            Options      = options,
            Requires     = dto.Requires ?? [],
            Iterate      = Yaml.ParseEnum(dto.Iterate,   IterationMode.None,          "Iterate"),
            Platform     = Yaml.ParseEnum(dto.Platform,  Platform.Any,                "Platform"),
            IoWeight     = Yaml.ParseEnum(dto.IoWeight,  IoWeight.Light,              "IoWeight"),
            MemoryWeight = Yaml.ParseEnum(dto.MemoryWeight, MemoryWeight.Light,       "MemoryWeight"),
            Elevation    = Yaml.ParseEnum(dto.Elevation, ElevationRequirement.None,   "Elevation"),
            Scope        = Yaml.ParseEnum(dto.Scope,     TargetScope.Any,             "Scope"),
            Priority     = dto.Priority ?? 50,
            SupportsVss  = dto.SupportsVss ?? false,
            DefaultEnabled = dto.DefaultEnabled ?? true,
            OutputName   = string.IsNullOrWhiteSpace(dto.OutputName) ? null : dto.OutputName.Trim(),
            Timeout      = dto.Timeout,
            SourcePath   = Path.GetFullPath(path)
        };
    }

    private static List<ModuleOption> ReadOptions(List<OptionDto>? source)
    {
        var result = new List<ModuleOption>();
        if (source is null) return result;

        for (var i = 0; i < source.Count; i++)
        {
            var o = source[i];
            if (string.IsNullOrWhiteSpace(o.Name))
                throw new FormatException($"Option {i + 1}: Name is required.");
            if (string.IsNullOrWhiteSpace(o.Expand))
                throw new FormatException($"Option '{o.Name}': Expand is required.");

            var kind = Yaml.ParseEnum(o.Kind, OptionKind.Flag, "Kind");
            var choices = o.Choices ?? [];

            if (kind == OptionKind.Choice && choices.Count == 0)
                throw new FormatException($"Option '{o.Name}': a Choice needs Choices.");

            var def = (o.Default ?? (kind == OptionKind.Flag ? "false" : "")).Trim();
            if (kind == OptionKind.Choice && def.Length > 0
                && !choices.Contains(def, StringComparer.OrdinalIgnoreCase))
                throw new FormatException($"Option '{o.Name}': default '{def}' is not one of its Choices.");

            if (result.Any(existing => string.Equals(existing.Name, o.Name, StringComparison.OrdinalIgnoreCase)))
                throw new FormatException($"Option '{o.Name}' is declared more than once.");

            result.Add(new ModuleOption
            {
                Name = o.Name.Trim(),
                Description = o.Description,
                Kind = kind,
                Choices = choices,
                Default = def,
                Expand = o.Expand.Trim()
            });
        }
        return result;
    }

    private static List<ProcessorDefinition> ReadProcessors(List<ProcessorDto>? source, string label)
    {
        var result = new List<ProcessorDefinition>();
        if (source is null) return result;

        for (var i = 0; i < source.Count; i++)
        {
            var p = source[i];
            if (string.IsNullOrWhiteSpace(p.Executable))
                throw new FormatException($"{label} {i + 1}: Executable is required.");
            if (string.IsNullOrWhiteSpace(p.CommandLine))
                throw new FormatException($"{label} {i + 1}: CommandLine is required.");

            result.Add(new ProcessorDefinition
            {
                Executable = p.Executable.Trim(),
                CommandLine = p.CommandLine.Trim(),
                ExportFormat = p.ExportFormat,
                ExportFile = p.ExportFile,
                WorkingDirectory = string.IsNullOrWhiteSpace(p.WorkingDirectory) ? null : p.WorkingDirectory.Trim(),
                ContinueOnError = p.ContinueOnError ?? false,
                ExpectedStderr = ReadPatterns(p.ExpectedStderr, $"{label} {i + 1}"),
                NoLogsArgument = string.IsNullOrWhiteSpace(p.NoLogsArgument) ? null : p.NoLogsArgument.Trim()
            });
        }
        return result;
    }

    private static List<string> ReadPatterns(List<string>? source, string label)
    {
        var result = new List<string>();
        if (source is null) return result;
        foreach (var pattern in source.Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            try
            {
                _ = new System.Text.RegularExpressions.Regex(pattern);
            }
            catch (ArgumentException ex)
            {
                throw new FormatException($"{label}: ExpectedStderr pattern '{pattern}' is not a valid regex: {ex.Message}");
            }
            result.Add(pattern);
        }
        return result;
    }

    private sealed class ModuleDto
    {
        public string? Description { get; set; }
        public string? Category { get; set; }
        public string? Author { get; set; }
        public string? Version { get; set; }
        public string? Id { get; set; }
        public string? ExportFormat { get; set; }
        public string? FileMask { get; set; }
        public List<ProcessorDto>? Processors { get; set; }
        public List<ProcessorDto>? Prepare { get; set; }
        public List<OptionDto>? Options { get; set; }
        public List<string>? Requires { get; set; }
        public string? Iterate { get; set; }
        public string? Platform { get; set; }
        public int? Priority { get; set; }
        public string? IoWeight { get; set; }
        public string? MemoryWeight { get; set; }
        public string? Elevation { get; set; }
        public string? Scope { get; set; }
        public bool? SupportsVss { get; set; }
        public bool? DefaultEnabled { get; set; }
        public string? OutputName { get; set; }
        public int? Timeout { get; set; }
    }

    private sealed class OptionDto
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? Kind { get; set; }
        public List<string>? Choices { get; set; }
        public string? Default { get; set; }
        public string? Expand { get; set; }
    }

    private sealed class ProcessorDto
    {
        public string? Executable { get; set; }
        public string? CommandLine { get; set; }
        public string? ExportFormat { get; set; }
        public string? ExportFile { get; set; }
        public string? WorkingDirectory { get; set; }
        public bool? ContinueOnError { get; set; }
        public List<string>? ExpectedStderr { get; set; }
        public string? NoLogsArgument { get; set; }
    }
}

namespace ArtefactForge.Core;

public static class LayoutLoader
{
    public static LoadResult<LayoutProfile> LoadDirectory(string directory)
    {
        var result = new LoadResult<LayoutProfile>();
        if (!Directory.Exists(directory))
        {
            result.Errors.Add(new LoadError(directory, "Layout directory not found."));
            return result;
        }

        foreach (var file in Directory.EnumerateFiles(directory, "*.layout", SearchOption.AllDirectories)
                                      .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            try { result.Items.Add(LoadFile(file)); }
            catch (Exception ex) { result.Errors.Add(new LoadError(file, ex.Message)); }
        }
        return result;
    }

    public static LayoutProfile LoadFile(string path)
    {
        var dto = Yaml.Deserializer.Deserialize<LayoutDto>(File.ReadAllText(path))
                  ?? throw new FormatException("File is empty or not valid YAML.");

        if (string.IsNullOrWhiteSpace(dto.Id))
            throw new FormatException("Id is required.");

        var detect = dto.Detect ?? new DetectDto();
        if (!detect.RootIsSelection.GetValueOrDefault() && !detect.DriveLetterFolder.GetValueOrDefault())
            throw new FormatException(
                "Detect must set either RootIsSelection or DriveLetterFolder - otherwise the root cannot be located.");

        var resolve = dto.Resolve ?? new ResolveDto();
        var offset = string.IsNullOrWhiteSpace(resolve.RootOffset) ? "." : resolve.RootOffset.Trim();
        if (offset is not ("." or "?"))
            throw new FormatException($"Resolve.RootOffset: '{offset}' is not supported. Use '.' (the selection) or '?' (the drive-letter folder).");

        return new LayoutProfile
        {
            Name        = dto.Name ?? dto.Id,
            Id          = dto.Id.Trim(),
            Priority    = dto.Priority ?? 50,
            Provisional = dto.Provisional ?? false,
            Description = dto.Description,
            Notes       = dto.Notes,
            Platform    = Yaml.ParseEnum(dto.Platform, Platform.Any, "Platform"),
            Detect = new LayoutDetectRules
            {
                RootIsSelection   = detect.RootIsSelection ?? false,
                Markers           = detect.Markers ?? [],
                MatchMode         = Yaml.ParseEnum(detect.MatchMode, MarkerMatchMode.Any, "Detect.MatchMode"),
                DriveLetterFolder = detect.DriveLetterFolder ?? false,
                MaxDepth          = detect.MaxDepth ?? 1
            },
            Resolve = new LayoutResolveRules
            {
                UserProfiles = dto.Resolve?.UserProfiles ?? ["Users/*"],
                RootOffset = offset,
                Unescape   = Yaml.ParseEnum(resolve.Unescape, UnescapeMode.None, "Resolve.Unescape")
            },
            SourcePath = Path.GetFullPath(path)
        };
    }

    private sealed class LayoutDto
    {
        public string? Name { get; set; }
        public string? Id { get; set; }
        public int? Priority { get; set; }
        public bool? Provisional { get; set; }
        public string? Description { get; set; }
        public string? Notes { get; set; }
        public string? Platform { get; set; }
        public DetectDto? Detect { get; set; }
        public ResolveDto? Resolve { get; set; }
    }

    private sealed class DetectDto
    {
        public bool? RootIsSelection { get; set; }
        public List<string>? Markers { get; set; }
        public string? MatchMode { get; set; }
        public bool? DriveLetterFolder { get; set; }
        public int? MaxDepth { get; set; }
    }

    private sealed class ResolveDto
    {
        public string? RootOffset { get; set; }
        public string? Unescape { get; set; }
        public List<string>? UserProfiles { get; set; }
    }
}

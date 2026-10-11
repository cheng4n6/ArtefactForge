using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArtefactForge.Core;

namespace ArtefactForge.Gui;

/// <summary>How the Setup tab lays out the modules. Both views edit the same selection.</summary>
public enum ModuleView
{
    /// <summary>Categories in one list, each collapsing to a single row with its modules beneath.</summary>
    List,

    /// <summary>Categories down the left; the chosen category's modules, described, on the right.</summary>
    Rail
}

/// <summary>
/// Per-user preferences for the GUI. They live in the user's profile rather than beside the
/// application, which an update replaces and which may sit on read-only media. One file for all
/// of them, so saving one preference never drops another.
/// </summary>
public static class Preferences
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ArtefactForge", "settings.json");

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    public sealed class Values
    {
        public string Theme { get; set; } = "Light";
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ModuleView ModuleView { get; set; } = ModuleView.List;

        /// <summary>Each evidence folder's last output folder and case name, newest first.</summary>
        public List<RememberedOutput> Outputs { get; set; } = [];

        /// <summary>The Run options card as last used.</summary>
        public SavedRunOptions RunOptions { get; set; } = new();
    }

    public static Values Current { get; } = Load();

    private static Values Load()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return new Values();
            return JsonSerializer.Deserialize<Values>(File.ReadAllText(SettingsPath)) ?? new Values();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // A damaged preference file is not worth an error at startup; the defaults apply.
            return new Values();
        }
    }

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(Current, Indented));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not saved means the next launch opens with the defaults; the change still applies now.
        }
    }
}

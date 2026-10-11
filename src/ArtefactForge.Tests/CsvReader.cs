using System.Text;

namespace ArtefactForge.Tests;

/// <summary>
/// Reads the CSV the parsers write (every cell quoted, "" for a quote inside one) into rows keyed by
/// column name. Unlike splitting on "," it survives a comma or quote inside a cell.
/// </summary>
internal static class CsvReader
{
    public static List<Dictionary<string, string>> Read(string path)
    {
        var lines = File.ReadAllLines(path);
        var header = Fields(lines[0].TrimStart('﻿'));
        return lines.Skip(1)
            .Select(l => header.Zip(Fields(l)).ToDictionary(p => p.First, p => p.Second))
            .ToList();
    }

    private static List<string> Fields(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted && c == '"' && i + 1 < line.Length && line[i + 1] == '"') { current.Append('"'); i++; }
            else if (c == '"') quoted = !quoted;
            else if (c == ',' && !quoted) { fields.Add(current.ToString()); current.Clear(); }
            else current.Append(c);
        }
        fields.Add(current.ToString());
        return fields;
    }
}

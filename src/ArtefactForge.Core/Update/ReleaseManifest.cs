using System.Text.Json;

namespace ArtefactForge.Core.Update;

/// <summary>
/// What a release says about itself: the contents of <c>artefactforge-latest.json</c>. Only ever
/// parsed after its signature has been verified, so every field here is the publisher's word.
/// </summary>
public sealed record ReleaseManifest
{
    public const string ExpectedProduct = "ArtefactForge";

    public required string Product { get; init; }
    public required string Version { get; init; }
    public string? Published { get; init; }

    /// <summary>The package zip, as a bare filename beside the manifest - never a path or a URL.</summary>
    public required string File { get; init; }

    public required long Size { get; init; }
    public required string Sha256 { get; init; }
    public string? Notes { get; init; }

    /// <summary>Parses and sanity-checks the manifest. Throws <see cref="UpdateException"/> on anything off.</summary>
    public static ReleaseManifest Parse(byte[] json)
    {
        JsonDocument document;
        try { document = JsonDocument.Parse(json); }
        catch (JsonException ex) { throw new UpdateException("The release manifest is not valid JSON: " + ex.Message); }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new UpdateException("The release manifest is not a JSON object.");

            var manifest = new ReleaseManifest
            {
                Product = Text(root, "product"),
                Version = Text(root, "version"),
                Published = OptionalText(root, "published"),
                File = Text(root, "file"),
                Size = root.TryGetProperty("size", out var size) && size.TryGetInt64(out var s) ? s
                    : throw new UpdateException("The release manifest has no size."),
                Sha256 = Text(root, "sha256"),
                Notes = OptionalText(root, "notes")
            };

            if (!string.Equals(manifest.Product, ExpectedProduct, StringComparison.Ordinal))
                throw new UpdateException($"The release manifest is for '{manifest.Product}', not {ExpectedProduct}.");

            // A bare name keeps the zip beside the manifest, in the same place the signature vouched for.
            if (manifest.File.IndexOfAny(['/', '\\', ':']) >= 0 || manifest.File.Contains("..") ||
                !manifest.File.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                throw new UpdateException($"The release manifest names an unexpected file: '{manifest.File}'.");

            if (manifest.Size <= 0) throw new UpdateException("The release manifest gives a size of zero.");

            if (manifest.Sha256.Length != 64 || !manifest.Sha256.All(Uri.IsHexDigit))
                throw new UpdateException("The release manifest's SHA-256 is not 64 hex characters.");

            return manifest;
        }
    }

    private static string Text(JsonElement root, string name) =>
        OptionalText(root, name) ?? throw new UpdateException($"The release manifest has no '{name}'.");

    private static string? OptionalText(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;
}

/// <summary>A refusal or failure in the update path, with a message fit to show the analyst as-is.</summary>
public sealed class UpdateException(string message, Exception? inner = null) : Exception(message, inner);

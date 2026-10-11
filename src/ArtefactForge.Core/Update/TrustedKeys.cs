namespace ArtefactForge.Core.Update;

/// <summary>
/// Public keys whose signatures this build accepts on a release. Compiled in, so changing the list
/// means shipping a release - which is the point: nothing published with a release can add to it.
///
/// Setting up (once), from the repository folder:
///   dotnet run --project src\ArtefactForge.Cli -- release keygen --out <key file, kept off this machine's source tree>
/// Keep the .key file and its password out of every release and out of this repository, with an offline
/// copy. Paste the public key it prints below. Until this list has an entry, the update check
/// reports that updates are not configured, and package.ps1 refuses to sign.
///
/// Rotating: add the new key beside the old one, ship a release signed with the old key, then sign
/// later releases with the new one and drop the old entry. If a private key is lost, every
/// installation has to be updated by hand once to a build that trusts its replacement.
/// </summary>
public static class TrustedKeys
{
    public static readonly IReadOnlyList<string> All =
    [
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE22hr8Fhp3c49w0qo2Dn41MP4SeX+O2vK/AbUw/U3oP0EbbSILHoetweGf5gdrZDLFilbtwP4xdhMMQdqPtV/2Q==",   // added 2026-10-06, fingerprint 41AF:0812:E66E:63A7:CCAC:EA16:4902:41BB
    ];
}

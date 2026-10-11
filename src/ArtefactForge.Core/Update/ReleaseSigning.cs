using System.Security.Cryptography;

namespace ArtefactForge.Core.Update;

/// <summary>
/// Signs and verifies release manifests. ECDSA P-256 over SHA-256, built into .NET, so neither the
/// application nor the packaging step needs a third-party library.
///
/// Why sign at all when the download is over HTTPS: releases are served from GitHub. HTTPS proves
/// the bytes came from that host; it says nothing about whether the repository or its releases
/// were tampered with. The private key never touches the host, so a compromised host can
/// serve old or broken files but cannot make a workstation install them.
/// </summary>
public static class ReleaseSigning
{
    private static readonly HashAlgorithmName Hash = HashAlgorithmName.SHA256;

    // The private key is protected with this when written. 600k PBKDF2 iterations is the current
    // OWASP figure for SHA-256; signing happens once per release, so the cost is irrelevant.
    private static readonly PbeParameters KeyProtection =
        new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);

    /// <summary>A new key pair: the private key as encrypted PEM, the public key as base64 SubjectPublicKeyInfo.</summary>
    public static (string PrivateKeyPem, string PublicKey) GenerateKey(string password)
    {
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("A password is required.", nameof(password));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (key.ExportEncryptedPkcs8PrivateKeyPem(password, KeyProtection),
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    }

    /// <summary>Signs the exact bytes given. Returns the signature as base64, the content of a .sig file.</summary>
    public static string Sign(byte[] data, string privateKeyPem, string password, out string publicKey)
    {
        using var key = ECDsa.Create();
        try { key.ImportFromEncryptedPem(privateKeyPem, password); }
        catch (CryptographicException ex) { throw new UpdateException("Could not open the signing key - wrong password?", ex); }

        publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        return Convert.ToBase64String(key.SignData(data, Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    /// <summary>
    /// True when <paramref name="signatureBase64"/> is a valid signature of <paramref name="data"/>
    /// by any of <paramref name="trustedKeys"/>. Never throws for a bad signature or a malformed key.
    /// </summary>
    public static bool Verify(byte[] data, string signatureBase64, IEnumerable<string> trustedKeys)
    {
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureBase64.Trim()); }
        catch (FormatException) { return false; }

        foreach (var trusted in trustedKeys)
        {
            try
            {
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(trusted), out _);
                if (key.VerifyData(data, signature, Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    return true;
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException)
            {
                // A malformed entry in the trusted list must not stop the others being tried.
            }
        }
        return false;
    }

    /// <summary>Short, readable identity of a public key - what the release notes show for checking by hand.</summary>
    public static string Fingerprint(string publicKey)
    {
        var hash = SHA256.HashData(Convert.FromBase64String(publicKey));
        var hex = Convert.ToHexString(hash, 0, 16);
        return string.Join(':', Enumerable.Range(0, hex.Length / 4).Select(i => hex.Substring(i * 4, 4)));
    }
}

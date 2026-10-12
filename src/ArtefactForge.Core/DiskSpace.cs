using System.Runtime.InteropServices;

namespace ArtefactForge.Core;

/// <summary>
/// Free space on the volume that holds a folder. <see cref="DriveInfo"/> only accepts a drive
/// letter, so it throws for a network share (\\server\share); Windows is asked directly instead,
/// which answers for a drive and a share alike.
/// </summary>
public static class DiskSpace
{
    /// <summary>
    /// Bytes this user can write on the volume that holds <paramref name="path"/>, or null when
    /// that cannot be read. The folder need not exist yet: its nearest existing parent is asked.
    /// </summary>
    public static long? Available(string path)
    {
        var folder = NearestExisting(Path.GetFullPath(path));
        if (folder is null) return null;

        if (OperatingSystem.IsWindows())
        {
            return GetDiskFreeSpaceEx(Path.TrimEndingDirectorySeparator(folder) + Path.DirectorySeparatorChar,
                out var available, out _, out _)
                ? (long)Math.Min(available, long.MaxValue)
                : null;
        }

        try { return new DriveInfo(folder).AvailableFreeSpace; }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException) { return null; }
    }

    private static string? NearestExisting(string path)
    {
        for (var current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            if (Directory.Exists(current)) return current;
        }
        return null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(
        string directory, out ulong freeBytesAvailable, out ulong totalBytes, out ulong totalFreeBytes);
}

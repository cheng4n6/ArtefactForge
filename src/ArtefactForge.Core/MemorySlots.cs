using System.Runtime.InteropServices;

namespace ArtefactForge.Core;

/// <summary>
/// How many memory-heavy modules may run at once, from the memory free when the run starts.
/// Measured on a 2 GB Velociraptor collection, the heaviest tool (Chainsaw's SRUM analysis) peaked
/// at 5.3 GB, so each slot allows for 6 GB. A 16 GB workstation with its usual load gets one, as
/// before; a 64 GB analysis server gets several.
/// </summary>
public static class MemorySlots
{
    public const long BytesPerSlot = 6L << 30;

    /// <summary>A ceiling, so a very large server still leaves the pool for the other modules.</summary>
    public const int Max = 8;

    /// <summary>One slot when free memory cannot be read: the safe answer, and the old behaviour.</summary>
    public static int For(long? availableBytes) =>
        availableBytes is { } bytes ? (int)Math.Clamp(bytes / BytesPerSlot, 1, Max) : 1;

    /// <summary>Physical memory free for new work now, or null when it cannot be read.</summary>
    public static long? Available()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
                return GlobalMemoryStatusEx(ref status) ? (long)Math.Min(status.AvailablePhysical, long.MaxValue) : null;
            }

            // MemAvailable is the kernel's own estimate of what new work can use without swapping.
            const string meminfo = "/proc/meminfo";
            if (!File.Exists(meminfo)) return null;
            var line = File.ReadLines(meminfo).FirstOrDefault(l => l.StartsWith("MemAvailable:", StringComparison.Ordinal));
            var kb = line?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1);
            return long.TryParse(kb, out var value) ? value * 1024 : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
}

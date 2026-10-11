using System.Runtime.Versioning;

// The suite is Windows-only in fact - the engine tests drive cmd.exe, and the access tests set
// NTFS ACLs through WindowsIdentity and FileSystemAccessRule. Saying so here is what stops the
// platform analyser raising CA1416 on every one of those calls (22 warnings on a clean build).
[assembly: SupportedOSPlatform("windows")]

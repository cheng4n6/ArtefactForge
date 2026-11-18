using System.Globalization;
using ArtefactForge.Lake;
using ArtefactForge.Lake.Cli;

return LakeCli.Run(args, Console.Out, Console.Error);

namespace ArtefactForge.Lake.Cli
{
    /// <summary>af-lake: builds an evidence lake from a case folder or a folder of parser output.</summary>
    public static class LakeCli
    {
        public const int ExitBuilt = 0;
        public const int ExitFailed = 1;
        public const int ExitUsage = 2;
        public const int ExitCheckLog = 3;

        public static int Run(string[] args, TextWriter output, TextWriter error)
        {
            var verb = args.ElementAtOrDefault(0)?.ToLowerInvariant();
            switch (verb)
            {
                case "build": return Build(args[1..], output, error);
                case "kinds": return Kinds(output);
                case null or "help" or "--help" or "-h" or "/?":
                    Usage(verb is null ? error : output);
                    return verb is null ? ExitUsage : ExitBuilt;
                default:
                    error.WriteLine($"Unknown command '{args[0]}'.");
                    Usage(error);
                    return ExitUsage;
            }
        }

        private static void Usage(TextWriter writer)
        {
            writer.WriteLine("af-lake - builds an evidence lake (one DuckDB file) from parser output");
            writer.WriteLine();
            writer.WriteLine("  af-lake build <folder> [--host NAME] [--memory-gb N] [--threads N] [--out DIR]");
            writer.WriteLine("      <folder> is an ArtefactForge case folder (one subfolder per host) or, with");
            writer.WriteLine("      --host, a folder of one machine's parser output. The lake is written to");
            writer.WriteLine("      <folder>\\_Lake\\case.duckdb, or to --out DIR.");
            writer.WriteLine("  af-lake kinds");
            writer.WriteLine("      Lists the kinds of parser output mapped into the timeline. Any other CSV is");
            writer.WriteLine("      kept in a raw table as unmapped.<parser>.");
            writer.WriteLine();
            writer.WriteLine("Exit codes: 0 built; 3 built, but some sources need a look (see lake.log);");
            writer.WriteLine("1 not built, or built but not swapped in; 2 bad arguments.");
        }

        private static int Kinds(TextWriter output)
        {
            foreach (var kind in KindRegistry.All)
            {
                output.WriteLine($"{kind.Kind,-22} {kind.Parser,-10} v{kind.MappingVersion}  {kind.Description}");
                output.WriteLine($"{"",-22} files: {string.Join("  ", kind.FileNames)}");
            }
            return ExitBuilt;
        }

        private static int Build(string[] args, TextWriter output, TextWriter error)
        {
            string? folder = null, host = null, outDirectory = null;
            long? memory = null;
            int? threads = null;
            for (var i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                string? Next()
                {
                    if (i + 1 < args.Length) return args[++i];
                    error.WriteLine($"{arg} needs a value.");
                    return null;
                }
                switch (arg.ToLowerInvariant())
                {
                    case "--host":
                        host = Next();
                        if (host is null) return ExitUsage;
                        break;
                    case "--out":
                        outDirectory = Next();
                        if (outDirectory is null) return ExitUsage;
                        break;
                    case "--memory-gb":
                        var gb = Next();
                        if (gb is null) return ExitUsage;
                        if (!double.TryParse(gb, NumberStyles.Float, CultureInfo.InvariantCulture, out var g) || g <= 0)
                        {
                            error.WriteLine($"--memory-gb takes a number of gigabytes above 0, not '{gb}'.");
                            return ExitUsage;
                        }
                        memory = (long)(g * 1024 * 1024 * 1024);
                        break;
                    case "--threads":
                        var t = Next();
                        if (t is null) return ExitUsage;
                        if (!int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n <= 0)
                        {
                            error.WriteLine($"--threads takes a whole number above 0, not '{t}'.");
                            return ExitUsage;
                        }
                        threads = n;
                        break;
                    default:
                        if (arg.StartsWith("--", StringComparison.Ordinal) || folder is not null)
                        {
                            error.WriteLine($"Unexpected argument '{arg}'.");
                            Usage(error);
                            return ExitUsage;
                        }
                        folder = arg;
                        break;
                }
            }

            if (folder is null)
            {
                error.WriteLine("build needs a folder.");
                Usage(error);
                return ExitUsage;
            }
            if (!Directory.Exists(folder))
            {
                error.WriteLine($"Folder not found: {folder}");
                return ExitUsage;
            }

            var options = new LakeOptions
            {
                SingleHost = host,
                MemoryLimitBytes = memory,
                Threads = threads,
                LakeDirectory = outDirectory,
                Producer = "af-lake " + (typeof(LakeCli).Assembly.GetName().Version?.ToString(3) ?? "")
            };
            using var cancel = new CancellationTokenSource();
            ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; cancel.Cancel(); };
            Console.CancelKeyPress += onCancel;
            try
            {
                var result = LakeBuilder.Build(folder, options, new Progress(output), cancel.Token);
                // Each source that needs a look was reported as it was loaded; the warnings that are
                // not about one source are repeated here so they are the last thing on screen.
                foreach (var warning in result.Warnings) error.WriteLine("Check: " + warning);

                switch (result.Outcome)
                {
                    case LakeOutcome.Built:
                        output.WriteLine(result.Message);
                        return ExitBuilt;
                    case LakeOutcome.BuiltCheckLog:
                        output.WriteLine(result.Message);
                        return ExitCheckLog;
                    default:
                        error.WriteLine(result.Message);
                        return ExitFailed;
                }
            }
            catch (OperationCanceledException)
            {
                error.WriteLine("Cancelled. No lake was written; the previous one, if any, is unchanged.");
                return ExitFailed;
            }
            finally
            {
                Console.CancelKeyPress -= onCancel;
            }
        }

        // Writes each line as it comes; Progress<T> would post to the thread pool and reorder them.
        private sealed class Progress(TextWriter output) : IProgress<string>
        {
            public void Report(string value) => output.WriteLine(value);
        }
    }
}

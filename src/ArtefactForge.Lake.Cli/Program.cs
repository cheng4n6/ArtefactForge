using System.Globalization;
using ArtefactForge.Lake.Queries;
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
                case "queries": return Queries(output);
                case "query": return Query(args[1..], output, error);
                case "ransomware": return RansomwareFiles(args[1..], output, error);
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
            writer.WriteLine("      kept in a raw table as unmapped.<parser>_<file>.");
            writer.WriteLine("  af-lake queries");
            writer.WriteLine("      Lists the saved queries, with what each finds and the parameters it takes.");
            writer.WriteLine("  af-lake query <folder> <name> [--out FILE] [--lake FILE] [--param NAME=VALUE ...]");
            writer.WriteLine("      Runs a saved query on <folder>\\_Lake\\case.duckdb (or --lake FILE) and writes");
            writer.WriteLine("      its rows to <folder>\\_Lake\\results\\<name>.csv, or to --out FILE. Files the");
            writer.WriteLine("      query reads from the case (such as Ransomware-Overrides.csv) are read from");
            writer.WriteLine("      <folder>. The lake is opened read-only.");
            writer.WriteLine("  af-lake ransomware <folder> [--out DIR] [--lake FILE]");
            writer.WriteLine("      Writes ArtefactForge's ransomware files (Ransomware.csv, and per host");
            writer.WriteLine("      Ransomware\\RansomwareSummary.csv, RansomwareEvidence.csv and Note\\) from the");
            writer.WriteLine("      lake's queries to <folder>\\_Lake\\results\\Ransomware, or to --out DIR, as a");
            writer.WriteLine("      lake build does.");
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

        private static int Queries(TextWriter output)
        {
            foreach (var query in LakeQueryCatalogue.All)
            {
                var kind = query.IsSetup ? " (setup: run by the queries that need it)" : "";
                output.WriteLine($"{query.Name,-26} {query.Category,-11} {query.Severity,-9} {query.Title}{kind}");
                if (query.Description.Length > 0) output.WriteLine($"{"",-26} {query.Description}");
                foreach (var parameter in query.Parameters)
                    output.WriteLine($"{"",-26} --param {parameter.Name}={parameter.Default}  {parameter.Description}");
                foreach (var input in query.Inputs)
                    output.WriteLine($"{"",-26} reads {input.FileName} from the case folder, if there is one");
            }
            return ExitBuilt;
        }

        private static int Query(string[] args, TextWriter output, TextWriter error)
        {
            string? folder = null, name = null, outFile = null, lake = null;
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
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
                    case "--out":
                        if ((outFile = Next()) is null) return ExitUsage;
                        break;
                    case "--lake":
                        if ((lake = Next()) is null) return ExitUsage;
                        break;
                    case "--param":
                        var pair = Next();
                        if (pair is null) return ExitUsage;
                        var at = pair.IndexOf('=');
                        if (at <= 0)
                        {
                            error.WriteLine($"--param takes NAME=VALUE, not '{pair}'.");
                            return ExitUsage;
                        }
                        parameters[pair[..at].Trim()] = pair[(at + 1)..].Trim();
                        break;
                    default:
                        if (arg.StartsWith("--", StringComparison.Ordinal) || (folder is not null && name is not null))
                        {
                            error.WriteLine($"Unexpected argument '{arg}'.");
                            Usage(error);
                            return ExitUsage;
                        }
                        if (folder is null) folder = arg; else name = arg;
                        break;
                }
            }

            if (folder is null || name is null)
            {
                error.WriteLine("query needs a folder and the name of a saved query (af-lake queries lists them).");
                return ExitUsage;
            }
            if (!Directory.Exists(folder))
            {
                error.WriteLine($"Folder not found: {folder}");
                return ExitUsage;
            }
            var query = LakeQueryCatalogue.Find(name);
            if (query is null)
            {
                error.WriteLine($"No saved query named '{name}'; af-lake queries lists them.");
                return ExitUsage;
            }
            if (query.IsSetup)
            {
                error.WriteLine($"{query.Name} is a setup step with no rows of its own; it runs with the queries that need it.");
                return ExitUsage;
            }
            var known = LakeQueryCatalogue.All.Where(q => q == query || query.Requires.Contains(q.Name))
                                              .SelectMany(q => q.Parameters).Select(p => p.Name)
                                              .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var unknown in parameters.Keys.Where(k => !known.Contains(k)))
            {
                error.WriteLine($"{query.Name} takes no parameter '{unknown}'.");
                return ExitUsage;
            }

            var database = lake ?? Path.Combine(folder, LakeNames.LakeFolder, LakeNames.DatabaseFile);
            if (!File.Exists(database))
            {
                error.WriteLine($"No lake at {database}: build one with af-lake build {folder}");
                return ExitFailed;
            }
            var target = outFile ?? Path.Combine(folder, LakeNames.LakeFolder, LakeNames.ResultsFolder, query.Name + ".csv");
            try
            {
                using var session = new LakeQuerySession(database, folder, parameters);
                var rows = session.RunToCsv(query, target);
                output.WriteLine($"{query.Title}: {rows:N0} row(s) written to {target}");
                return ExitBuilt;
            }
            catch (Exception ex) when (ex is System.Data.Common.DbException or IOException or UnauthorizedAccessException
                                           or InvalidDataException)
            {
                error.WriteLine($"{query.Name} failed: {ex.Message.Split('\n')[0].Trim()}");
                return ExitFailed;
            }
        }

        private static int RansomwareFiles(string[] args, TextWriter output, TextWriter error)
        {
            string? folder = null, outDirectory = null, lake = null;
            for (var i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                switch (arg.ToLowerInvariant())
                {
                    case "--out" when i + 1 < args.Length:
                        outDirectory = args[++i];
                        break;
                    case "--lake" when i + 1 < args.Length:
                        lake = args[++i];
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
            if (folder is null || !Directory.Exists(folder))
            {
                error.WriteLine(folder is null ? "ransomware needs a case folder." : $"Folder not found: {folder}");
                return ExitUsage;
            }
            var lakeDirectory = Path.Combine(folder, LakeNames.LakeFolder);
            var database = lake ?? Path.Combine(lakeDirectory, LakeNames.DatabaseFile);
            if (!File.Exists(database))
            {
                error.WriteLine($"No lake at {database}: build one with af-lake build {folder}");
                return ExitFailed;
            }
            var root = outDirectory ?? RansomwareResults.OutputRootFor(lakeDirectory);
            try
            {
                using var session = new LakeQuerySession(database, folder);
                var written = RansomwareResults.Write(session, root);
                output.WriteLine($"Ransomware files in {root}: {written.Describe()}");
                return ExitBuilt;
            }
            catch (Exception ex) when (ex is System.Data.Common.DbException or IOException or UnauthorizedAccessException
                                           or InvalidDataException)
            {
                error.WriteLine($"The ransomware queries failed: {ex.Message.Split('\n')[0].Trim()}");
                return ExitFailed;
            }
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

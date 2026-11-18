using System.Data.Common;
using System.Diagnostics;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using DuckDB.NET.Data;

namespace ArtefactForge.Lake;

/// <summary>
/// Builds &lt;Case&gt;\_Lake\case.duckdb from the parser output in a case's host folders.
/// </summary>
public static class LakeBuilder
{
    /// <summary>The lake's own format version, in lake_meta. Bumped when a reader of the old one would misread it.</summary>
    public const int LakeFormatVersion = 1;

    // A row bigger than this is rejected rather than read. EvtxECmd's Payload column holds whole
    // event XML as JSON, and a few events run to megabytes; DuckDB's default limit is 2 MB.
    private const long MaxLineBytes = 32L * 1024 * 1024;

    private static readonly string[] MetaColumns = ["host", "source_id", "row_no"];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Builds the lake for <paramref name="caseDirectory"/>. The lake is built as case.duckdb.new and
    /// moved over case.duckdb only when complete, so a reader never sees half a lake; if the old
    /// file is open elsewhere the new one is left beside it and the result says so. lake.log and
    /// build.json in the lake folder record every source, loaded or not, and why.
    /// </summary>
    public static LakeResult Build(string caseDirectory, LakeOptions? options = null,
        IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        options ??= new LakeOptions();
        var started = DateTime.UtcNow;
        var clock = Stopwatch.StartNew();
        caseDirectory = Path.GetFullPath(caseDirectory);
        var lakeDirectory = Path.GetFullPath(options.LakeDirectory ?? Path.Combine(caseDirectory, LakeNames.LakeFolder));

        if (!Directory.Exists(caseDirectory))
            return new LakeResult
            {
                Outcome = LakeOutcome.Failed, Message = $"Folder not found: {caseDirectory}",
                StartedUtc = started, Duration = clock.Elapsed
            };

        Directory.CreateDirectory(lakeDirectory);
        var tempDirectory = Path.Combine(lakeDirectory, LakeNames.TempFolder);
        var finalPath = Path.Combine(lakeDirectory, LakeNames.DatabaseFile);
        var newPath = finalPath + ".new";

        using var log = new LakeLog(Path.Combine(lakeDirectory, LakeNames.LogFile), progress);
        log.Write($"Evidence lake build of {caseDirectory}");
        log.Write($"Lake folder {lakeDirectory}; producer {options.Producer}");
        foreach (var note in options.Notes) log.Write(note);

        var warnings = new List<string>();
        var results = new List<LakeSourceResult>();
        string? duckDbVersion = null;
        LakeResult Finish(LakeOutcome outcome, string message, string? database, IReadOnlyList<string> hosts,
            long rawRows, long timelineRows)
        {
            var result = new LakeResult
            {
                Outcome = outcome, Message = message, DatabasePath = database, LakeDirectory = lakeDirectory,
                Hosts = hosts, Sources = results, Warnings = warnings, RawRows = rawRows,
                TimelineRows = timelineRows, DuckDbVersion = duckDbVersion, StartedUtc = started,
                Duration = clock.Elapsed
            };
            log.Write(message, report: false);
            WriteBuildFile(Path.Combine(lakeDirectory, LakeNames.BuildFile), result, options);
            return result;
        }

        IReadOnlyList<DiscoveredHost> hosts;
        try { hosts = SourceDiscovery.Discover(caseDirectory, options.SingleHost); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Finish(LakeOutcome.Failed, $"Could not list the host folders: {ex.Message}", null, [], 0, 0);
        }
        var hostNames = hosts.Select(h => h.Name).ToList();
        if (hosts.Count == 0)
            return Finish(LakeOutcome.Failed,
                $"No host folders in {caseDirectory} (a host is a subfolder not starting with '_'; " +
                "use --host NAME for a folder holding one machine's output)", null, [], 0, 0);

        DeleteIfPresent(newPath);
        DeleteIfPresent(newPath + ".wal");
        long rawRows = 0, timelineRows = 0;
        try
        {
            Directory.CreateDirectory(tempDirectory);
            using (var db = LakeDatabase.Open(newPath, options, tempDirectory))
            {
                duckDbVersion = LakeDatabase.Scalar(db, "SELECT version()") as string;
                log.Write($"DuckDB {duckDbVersion}; memory_limit {LakeDatabase.Scalar(db, "SELECT current_setting('memory_limit')")}, " +
                          $"threads {LakeDatabase.Scalar(db, "SELECT current_setting('threads')")}");
                LakeDatabase.Execute(db, KindRegistry.ReadResource(typeof(LakeBuilder).Assembly, "Schema/schema.sql"));
                WriteHosts(db, hosts, warnings, log);

                var sourceId = 0;
                var planned = new List<(DiscoveredSource Source, int Id)>();
                foreach (var host in hosts)
                    foreach (var source in host.Sources)
                        planned.Add((source, ++sourceId));
                // A case folder's own case-wide files; a folder given as one host has none.
                if (options.SingleHost is null)
                    foreach (var source in SourceDiscovery.CaseFiles(caseDirectory))
                        planned.Add((source, ++sourceId));

                var loads = new Dictionary<int, SourceLoad>();
                foreach (var (source, id) in planned)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    loads[id] = LoadSource(db, source, id, log);
                }

                var timelineCounts = MapKinds(db, planned, loads, log, cancellationToken);
                foreach (var (source, id) in planned)
                {
                    var load = loads[id];
                    results.Add(new LakeSourceResult
                    {
                        SourceId = id, Host = source.Host, Path = source.Path, Kind = source.Kind,
                        Parser = source.Parser, ParserVersion = source.ParserVersion,
                        OutputStatus = source.OutputStatus, Status = load.Status, Reason = load.Reason,
                        RowsLoaded = load.Rows, RowsRejected = load.Rejected, TimeUnread = load.TimeUnread, TimeConverted = load.TimeConverted,
                        TimelineRows = timelineCounts.GetValueOrDefault(id)
                    });
                }
                WriteSources(db, planned, loads, results);

                rawRows = results.Sum(r => r.RowsLoaded);
                timelineRows = LakeDatabase.Count(db, "SELECT count(*) FROM timeline");
                WriteMeta(db, options, started, duckDbVersion);
                LakeDatabase.Execute(db, "CHECKPOINT");
            }
        }
        catch (OperationCanceledException)
        {
            DeleteIfPresent(newPath);
            DeleteIfPresent(newPath + ".wal");
            DeleteFolder(tempDirectory);
            log.Write("Cancelled; no lake was written and the previous one, if any, is unchanged.");
            throw;
        }
        catch (Exception ex) when (ex is DbException or IOException or UnauthorizedAccessException
                                       or InvalidOperationException or InvalidDataException)
        {
            DeleteIfPresent(newPath);
            DeleteIfPresent(newPath + ".wal");
            DeleteFolder(tempDirectory);
            return Finish(LakeOutcome.Failed,
                $"The lake could not be built: {FirstLine(ex.Message)}. The previous lake, if any, is unchanged.",
                null, hostNames, 0, 0);
        }

        if (options.RunAnalyses) RunAnalyses(newPath, caseDirectory, lakeDirectory, tempDirectory, options, warnings, log, cancellationToken);

        DeleteFolder(tempDirectory);
        if (Directory.Exists(tempDirectory)) warnings.Add($"Could not remove the spill folder {tempDirectory}");

        foreach (var r in results.Where(r => r.NeedsReview))
            log.Write($"Check: {r.Host}/{r.Path}: {r.Status}{(r.Reason is null ? "" : " - " + r.Reason)}" +
                      (r.RowsRejected > 0 ? $" ({r.RowsRejected} rows rejected)" : ""));
        if (results.All(r => r.Status != SourceStatus.Loaded))
            warnings.Add("No source was loaded: the lake is empty");

        var summary = $"{hostNames.Count} host(s), {results.Count(r => r.Status == SourceStatus.Loaded)} of " +
                      $"{results.Count} source(s) loaded, {rawRows:N0} raw rows, {timelineRows:N0} timeline rows";
        var review = results.Any(r => r.NeedsReview) || warnings.Count > 0;

        var swapProblem = Swap(newPath, finalPath);
        if (swapProblem is not null)
            return Finish(LakeOutcome.NotSwapped,
                $"Built {summary}, but {finalPath} could not be replaced ({swapProblem}); it is probably open in " +
                $"another program. The new lake is {newPath}: close the other program and build again, or open that file.",
                newPath, hostNames, rawRows, timelineRows);

        return Finish(review ? LakeOutcome.BuiltCheckLog : LakeOutcome.Built,
            review ? $"Built {finalPath}: {summary}. Some sources need a look: see {LakeNames.LogFile}."
                   : $"Built {finalPath}: {summary}.",
            finalPath, hostNames, rawRows, timelineRows);
    }

    /// <summary>
    /// The saved analyses over the finished lake, before it is swapped in, each writing its files
    /// under &lt;lake&gt;\results. One that fails is a warning, so the build needs a look; the lake
    /// itself stands.
    /// </summary>
    private static void RunAnalyses(string database, string caseDirectory, string lakeDirectory, string tempDirectory,
        LakeOptions options, List<string> warnings, LakeLog log, CancellationToken cancellationToken)
    {
        var outputRoot = Queries.RansomwareResults.OutputRootFor(lakeDirectory);
        try
        {
            Directory.CreateDirectory(tempDirectory);
            using var session = new Queries.LakeQuerySession(database, caseDirectory, null, options, tempDirectory);
            var written = Queries.RansomwareResults.Write(session, outputRoot, cancellationToken);
            log.Write($"Ransomware from the lake's queries in {outputRoot}: {written.Describe()}");
        }
        catch (Exception ex) when (ex is DbException or IOException or UnauthorizedAccessException or InvalidDataException
                                       or InvalidOperationException)
        {
            var warning = $"The ransomware queries failed, so {outputRoot} is missing or incomplete: {FirstLine(ex.Message)}";
            warnings.Add(warning);
            log.Write(warning);
        }
    }

    private sealed record SourceLoad(string Status, string? Reason, long Rows, long Rejected, string? RawTable)
    {
        public long TimeUnread { get; init; }
        public long TimeConverted { get; init; }
    }

    private static SourceLoad LoadSource(DuckDBConnection db, DiscoveredSource source, int id, LakeLog log)
    {
        switch (source.Plan)
        {
            case SourcePlan.Skip:
                log.Write($"Skipped {source.Host}/{source.Path}: {source.Reason}");
                return new SourceLoad(SourceStatus.Skipped, source.Reason, 0, 0, null);
            case SourcePlan.Fail:
                log.Write($"Failed {source.Host}/{source.Path}: {source.Reason}");
                return new SourceLoad(SourceStatus.Failed, source.Reason, 0, 0, null);
        }

        var table = LakeNames.RawTable(source.Kind!);
        try
        {
            var (rows, rejected, renamed) = LoadCsv(db, source.FullPath, table, source.Host, id);
            var notes = new List<string>();
            if (source.Reason is not null) notes.Add(source.Reason);
            if (renamed.Count > 0)
                notes.Add("columns renamed because the lake uses the name: " + string.Join(", ", renamed));
            if (rejected > 0)
                notes.Add($"{rejected} row(s) could not be read and were left out; row_no counts the rows that were read");
            var reason = notes.Count == 0 ? null : string.Join("; ", notes);
            var status = source.Plan == SourcePlan.HeaderMismatch ? SourceStatus.HeaderMismatch : SourceStatus.Loaded;
            log.Write($"Loaded {source.Host}/{source.Path} as {source.Kind}: {rows:N0} rows" +
                      (reason is null ? "" : $" ({reason})"));
            return new SourceLoad(status, reason, rows, rejected, table);
        }
        catch (DbException ex)
        {
            var reason = $"could not be read: {FirstLine(ex.Message)}";
            log.Write($"Failed {source.Host}/{source.Path}: {reason}");
            return new SourceLoad(SourceStatus.Failed, reason, 0, 0, null);
        }
    }

    /// <summary>
    /// Reads one CSV into <paramref name="table"/>, every column as text, plus host, source_id and
    /// row_no. The table is created from the first file's columns and widened when a later file has
    /// columns it lacks, so files of one kind from different tool versions share it. Rows DuckDB
    /// cannot read are counted, not silently dropped.
    /// </summary>
    private static (long Rows, long Rejected, List<string> Renamed) LoadCsv(DuckDBConnection db, string path,
        string table, string host, int sourceId)
    {
        LakeDatabase.Execute(db, "DROP TABLE IF EXISTS temp.lake_src; DROP TABLE IF EXISTS temp.lake_reject_errors; " +
                                 "DROP TABLE IF EXISTS temp.lake_reject_scans");
        var lineBytes = MaxLineBytes.ToString(CultureInfo.InvariantCulture);
        LakeDatabase.Execute(db,
            $"CREATE TEMP TABLE lake_src AS SELECT * FROM read_csv({LakeDatabase.Literal(path)}, " +
            "header = true, all_varchar = true, auto_detect = true, delim = ',', quote = '\"', escape = '\"', " +
            $"max_line_size = {lineBytes}, buffer_size = {(MaxLineBytes * 2).ToString(CultureInfo.InvariantCulture)}, " +
            "store_rejects = true, rejects_table = 'lake_reject_errors', rejects_scan = 'lake_reject_scans')");
        var rejected = LakeDatabase.Count(db,
            "SELECT count(DISTINCT (file_id, line)) FROM temp.lake_reject_errors");

        var columns = ColumnsOf(db, "temp", "lake_src");
        var renamed = new List<string>();
        foreach (var clash in columns.Where(c => MetaColumns.Contains(c, StringComparer.OrdinalIgnoreCase)).ToList())
        {
            var newName = "csv_" + clash;
            LakeDatabase.Execute(db, $"ALTER TABLE temp.lake_src RENAME COLUMN {LakeDatabase.Identifier(clash)} " +
                                     $"TO {LakeDatabase.Identifier(newName)}");
            renamed.Add($"{clash} to {newName}");
        }
        columns = ColumnsOf(db, "temp", "lake_src");

        var existing = ColumnsOf(db, "main", table);
        if (existing.Count == 0)
        {
            var definitions = new[] { "host VARCHAR NOT NULL", "source_id INTEGER NOT NULL", "row_no BIGINT NOT NULL" }
                .Concat(columns.Select(c => $"{LakeDatabase.Identifier(c)} VARCHAR"));
            LakeDatabase.Execute(db, $"CREATE TABLE {LakeDatabase.Identifier(table)} ({string.Join(", ", definitions)})");
        }
        else
        {
            var have = new HashSet<string>(existing, StringComparer.OrdinalIgnoreCase);
            foreach (var column in columns.Where(c => !have.Contains(c)))
                LakeDatabase.Execute(db, $"ALTER TABLE {LakeDatabase.Identifier(table)} ADD COLUMN " +
                                         $"{LakeDatabase.Identifier(column)} VARCHAR");
        }

        LakeDatabase.Execute(db,
            $"INSERT INTO {LakeDatabase.Identifier(table)} BY NAME " +
            $"SELECT *, {LakeDatabase.Literal(host)} AS host, {sourceId.ToString(CultureInfo.InvariantCulture)} AS source_id, " +
            "rowid + 1 AS row_no FROM temp.lake_src ORDER BY rowid");
        var rows = LakeDatabase.Count(db, "SELECT count(*) FROM temp.lake_src");
        LakeDatabase.Execute(db, "DROP TABLE temp.lake_src");
        return (rows, rejected, renamed);
    }

    // "temp" is the temporary tables' database; anything else means the lake file itself.
    private static List<string> ColumnsOf(DuckDBConnection db, string database, string table)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT column_name FROM duckdb_columns() " +
                              "WHERE database_name = (CASE WHEN $database = 'temp' THEN 'temp' ELSE current_database() END) " +
                              "AND schema_name = 'main' AND table_name = $table ORDER BY column_index";
        command.Parameters.Add(new DuckDBParameter("database", database));
        command.Parameters.Add(new DuckDBParameter("table", table));
        using var reader = command.ExecuteReader();
        var columns = new List<string>();
        while (reader.Read()) columns.Add(reader.GetString(0));
        return columns;
    }

    /// <summary>
    /// Runs each mapped kind's map.sql over its raw table into timeline. A mapping that fails is
    /// reported against every source of that kind; their raw rows stay.
    /// </summary>
    private static Dictionary<int, long> MapKinds(DuckDBConnection db, List<(DiscoveredSource Source, int Id)> planned,
        Dictionary<int, SourceLoad> loads, LakeLog log, CancellationToken cancellationToken)
    {
        var mappedKinds = planned
            .Where(p => p.Source.Plan == SourcePlan.Mapped && loads[p.Id].Status == SourceStatus.Loaded)
            .Select(p => p.Source.Definition!)
            .DistinctBy(k => k.Kind)
            .Where(k => k.MapSql is not null)
            .OrderBy(k => k.Kind, StringComparer.Ordinal)
            .ToList();

        foreach (var kind in mappedKinds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var have = new HashSet<string>(ColumnsOf(db, "main", kind.RawTable), StringComparer.OrdinalIgnoreCase);
                foreach (var column in kind.OptionalColumns.Where(c => !have.Contains(c)))
                    LakeDatabase.Execute(db, $"ALTER TABLE {LakeDatabase.Identifier(kind.RawTable)} ADD COLUMN " +
                                             $"{LakeDatabase.Identifier(column)} VARCHAR");
                var before = LakeDatabase.Count(db, "SELECT count(*) FROM timeline");
                LakeDatabase.Execute(db, $"INSERT INTO timeline BY NAME\n{kind.MapSql}");
                var added = LakeDatabase.Count(db, "SELECT count(*) FROM timeline") - before;
                log.Write($"Mapped {kind.Kind} (mapping version {kind.MappingVersion}): {added:N0} timeline rows");
                CountUnreadTimes(db, kind, planned, loads, log);
            }
            catch (DbException ex)
            {
                var reason = $"loaded raw, but its mapping into the timeline failed: {FirstLine(ex.Message)}";
                log.Write($"Failed mapping {kind.Kind}: {FirstLine(ex.Message)}");
                foreach (var (source, id) in planned.Where(p => p.Source.Definition == kind))
                    loads[id] = loads[id] with { Status = SourceStatus.Failed, Reason = reason };
            }
        }

        var counts = new Dictionary<int, long>();
        using var command = db.CreateCommand();
        command.CommandText = "SELECT source_id, count(*) FROM timeline GROUP BY source_id";
        using var reader = command.ExecuteReader();
        while (reader.Read()) counts[reader.GetInt32(0)] = reader.GetInt64(1);
        return counts;
    }

    /// <summary>
    /// Rows of a kind whose time column holds something the mapping could not read as a time.
    /// They stay in the raw table but are not in the timeline, so each source says how many.
    /// </summary>
    private static void CountUnreadTimes(DuckDBConnection db, KindDefinition kind,
        List<(DiscoveredSource Source, int Id)> planned, Dictionary<int, SourceLoad> loads, LakeLog log)
    {
        if (kind.TimeColumn is null) return;
        var column = "r." + LakeDatabase.Identifier(kind.TimeColumn);
        var empty = $"nullif(trim({column}), '') IS NULL";
        // With a local time column, an empty time is converted where the host has a usable zone.
        var converted = kind.LocalTimeColumn is null
            ? "NULL"
            : $"lake_local_utc(r.{LakeDatabase.Identifier(kind.LocalTimeColumn)}, z.iana, z.fixed_offset)";
        var counts = new List<(int Id, long Unread, long Empty, long Converted, string? Zone)>();
        using (var command = db.CreateCommand())
        {
            command.CommandText =
                $"SELECT r.source_id, count(*) FILTER (WHERE NOT ({empty}) AND {kind.TimeFunction}({column}) IS NULL), " +
                $"count(*) FILTER (WHERE {empty} AND {converted} IS NULL), " +
                $"count(*) FILTER (WHERE {empty} AND {converted} IS NOT NULL), " +
                "any_value(coalesce(z.iana, z.fixed_offset)) " +
                $"FROM {LakeDatabase.Identifier(kind.RawTable)} r LEFT JOIN host_zones z ON z.host = r.host GROUP BY r.source_id";
            using var reader = command.ExecuteReader();
            while (reader.Read())
                counts.Add((reader.GetInt32(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3),
                            reader.IsDBNull(4) ? null : reader.GetString(4)));
        }
        foreach (var (id, unread, emptyRows, convertedRows, zone) in counts)
        {
            if (!loads.TryGetValue(id, out var load)) continue;
            var source = planned.First(p => p.Id == id).Source;
            if (convertedRows > 0)
            {
                loads[id] = load = load with { TimeConverted = convertedRows };
                log.Write($"{source.Host}/{source.Path}: {convertedRows:N0} row(s) with only the host's local time converted to UTC " +
                          $"with its time zone ({zone}); their ts_desc says so");
            }
            var notes = new List<string>();
            if (unread > 0)
                notes.Add($"{unread:N0} row(s) with a {kind.TimeColumn} that could not be read as a time: in the raw table, not the timeline");
            var emptyCounted = kind.EmptyTimeNote is not null && emptyRows > 0;
            if (emptyCounted) notes.Add($"{emptyRows:N0} row(s) {kind.EmptyTimeNote}: in the raw table, not the timeline");
            if (notes.Count == 0) continue;
            var note = string.Join("; ", notes);
            var count = unread + (emptyCounted ? emptyRows : 0);
            loads[id] = load with { Reason = load.Reason is null ? note : load.Reason + "; " + note, TimeUnread = count };
            log.Write($"Check {source.Host}/{source.Path}: {note}");
        }
    }

    private static void WriteHosts(DuckDBConnection db, IReadOnlyList<DiscoveredHost> hosts, List<string> warnings, LakeLog log)
    {
        foreach (var host in hosts)
        {
            using var command = db.CreateCommand();
            command.CommandText = "INSERT INTO hosts VALUES ($host, $hostname, $platform, $tz, $collected, $collector, $producer, $manifest)";
            command.Parameters.Add(new DuckDBParameter("host", host.Name));
            command.Parameters.Add(new DuckDBParameter("hostname", (object?)host.Info?.Hostname ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("platform", (object?)host.Info?.Platform ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("tz", (object?)host.Info?.TimeZone ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("collected", (object?)host.Info?.CollectedUtc ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("collector", (object?)host.Info?.Collector ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("producer", (object?)host.Producer ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("manifest", host.FromManifest));
            command.ExecuteNonQuery();

            var how = host.FromManifest ? "outputs.json" : "file names and headers (no outputs.json)";
            log.Write($"Host {host.Name}: {host.Sources.Count} file(s), found from {how}");
            if (host.ManifestProblem is not null)
            {
                var warning = $"{host.Name}: outputs.json could not be used ({host.ManifestProblem}); its folder was searched instead";
                warnings.Add(warning);
                log.Write(warning);
            }
            if (host.Sources.Count == 0)
            {
                var warning = $"{host.Name}: no CSV files found";
                warnings.Add(warning);
                log.Write(warning);
            }
        }
    }

    private static void WriteSources(DuckDBConnection db, List<(DiscoveredSource Source, int Id)> planned,
        Dictionary<int, SourceLoad> loads, List<LakeSourceResult> results)
    {
        var byId = results.ToDictionary(r => r.SourceId);
        foreach (var (source, id) in planned)
        {
            var load = loads[id];
            var result = byId[id];
            var mapped = source.Plan == SourcePlan.Mapped && load.Status == SourceStatus.Loaded && source.Definition?.MapSql is not null;
            using var command = db.CreateCommand();
            command.CommandText = "INSERT INTO sources VALUES ($id, $host, $path, $kind, $parser, $version, $outputStatus, " +
                                  "$status, $reason, $raw, $mapping, $mappingVersion, $rows, $rejected, $timeline, $size, $mtime, $unread, $converted)";
            command.Parameters.Add(new DuckDBParameter("id", id));
            command.Parameters.Add(new DuckDBParameter("host", source.Host));
            command.Parameters.Add(new DuckDBParameter("path", source.Path));
            command.Parameters.Add(new DuckDBParameter("kind", (object?)source.Kind ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("parser", (object?)source.Parser ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("version", source.ParserVersion));
            command.Parameters.Add(new DuckDBParameter("outputStatus", (object?)source.OutputStatus ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("status", load.Status));
            command.Parameters.Add(new DuckDBParameter("reason", (object?)load.Reason ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("raw", (object?)load.RawTable ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("mapping", mapped ? (object)source.Kind! : DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("mappingVersion", mapped ? (object)source.Definition!.MappingVersion : DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("rows", load.Rows));
            command.Parameters.Add(new DuckDBParameter("unread", load.TimeUnread));
            command.Parameters.Add(new DuckDBParameter("converted", load.TimeConverted));
            command.Parameters.Add(new DuckDBParameter("rejected", load.Rejected));
            command.Parameters.Add(new DuckDBParameter("timeline", result.TimelineRows));
            command.Parameters.Add(new DuckDBParameter("size", (object?)source.Size ?? DBNull.Value));
            command.Parameters.Add(new DuckDBParameter("mtime", (object?)source.ModifiedUtc ?? DBNull.Value));
            command.ExecuteNonQuery();
        }
    }

    private static void WriteMeta(DuckDBConnection db, LakeOptions options, DateTime started, string? duckDbVersion)
    {
        var values = new Dictionary<string, string?>
        {
            ["lake_format_version"] = LakeFormatVersion.ToString(CultureInfo.InvariantCulture),
            ["built_utc"] = started.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ["producer"] = options.Producer,
            ["library"] = typeof(LakeBuilder).Assembly.GetName().Version?.ToString(),
            ["duckdb_version"] = duckDbVersion,
            ["kinds"] = string.Join(", ", KindRegistry.All.Select(k => $"{k.Kind} v{k.MappingVersion}"))
        };
        // Read back from the connection that built the lake, so the record shows what was in force.
        foreach (var setting in new[] { "autoinstall_known_extensions", "autoload_known_extensions", "memory_limit", "threads" })
            values["setting." + setting] = LakeDatabase.Scalar(db, $"SELECT current_setting('{setting}')")?.ToString();

        foreach (var (key, value) in values)
        {
            using var command = db.CreateCommand();
            command.CommandText = "INSERT INTO lake_meta VALUES ($key, $value)";
            command.Parameters.Add(new DuckDBParameter("key", key));
            command.Parameters.Add(new DuckDBParameter("value", (object?)value ?? DBNull.Value));
            command.ExecuteNonQuery();
        }
    }

    /// <summary>
    /// Moves the new lake over the old. A stale write-ahead log beside the old file is removed
    /// first: DuckDB would replay it into the new file. Returns why it failed, or null.
    /// </summary>
    private static string? Swap(string newPath, string finalPath)
    {
        try
        {
            if (File.Exists(finalPath + ".wal")) File.Delete(finalPath + ".wal");
            File.Move(newPath, finalPath, overwrite: true);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ex.Message.TrimEnd('.');
        }
    }

    private static void WriteBuildFile(string path, LakeResult result, LakeOptions options)
    {
        var record = new
        {
            format = "evidence-lake-build",
            formatVersion = 1,
            startedUtc = result.StartedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            durationSeconds = Math.Round(result.Duration.TotalSeconds, 1),
            producer = options.Producer,
            duckDbVersion = result.DuckDbVersion,
            result = result.Outcome switch
            {
                LakeOutcome.Built => "built",
                LakeOutcome.BuiltCheckLog => "checklog",
                LakeOutcome.NotSwapped => "notswapped",
                _ => "failed"
            },
            message = result.Message,
            database = result.DatabasePath is null ? null : Path.GetFileName(result.DatabasePath),
            hosts = result.Hosts,
            rawRows = result.RawRows,
            timelineRows = result.TimelineRows,
            sourcesLoaded = result.Loaded,
            sourcesSkipped = result.Skipped,
            sourcesHeaderMismatch = result.Mismatched,
            sourcesFailed = result.FailedSources,
            warnings = result.Warnings,
            sources = result.Sources.Select(s => new
            {
                s.SourceId, s.Host, s.Path, s.Kind, s.Parser, s.ParserVersion, s.OutputStatus, s.Status, s.TimeUnread, s.TimeConverted,
                s.Reason, s.RowsLoaded, s.RowsRejected, s.TimelineRows
            })
        };
        try { File.WriteAllText(path, JsonSerializer.Serialize(record, JsonOptions)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The result still carries everything; the log says the file is missing.
        }
    }

    private static void DeleteIfPresent(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A leftover from an earlier build that cannot be removed is overwritten or reported later.
        }
    }

    private static void DeleteFolder(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Reported by the caller, which checks whether the folder is still there.
        }
    }

    private static string FirstLine(string text)
    {
        var line = text.Split('\n', 2)[0].Trim();
        return line.TrimEnd('.');
    }
}

/// <summary>lake.log: written as the build goes, so a build that dies part-way still says how far it got.</summary>
internal sealed class LakeLog : IDisposable
{
    private readonly StreamWriter? _writer;
    private readonly IProgress<string>? _progress;

    public LakeLog(string path, IProgress<string>? progress)
    {
        _progress = progress;
        try { _writer = new StreamWriter(path, append: false) { AutoFlush = true }; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            progress?.Report($"Could not write {path}: {ex.Message}");
        }
    }

    public void Write(string line, bool report = true)
    {
        _writer?.WriteLine($"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z  {line}");
        if (report) _progress?.Report(line);
    }

    public void Dispose() => _writer?.Dispose();
}

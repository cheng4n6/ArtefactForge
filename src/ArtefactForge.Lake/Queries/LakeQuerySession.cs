using System.Data.Common;
using System.Globalization;
using System.Text;
using DuckDB.NET.Data;

namespace ArtefactForge.Lake.Queries;

/// <summary>
/// Runs saved queries against a built lake. The lake is opened read-only: what a query makes
/// (its setup tables, the case files it reads, stand-ins for tables the lake lacks) lives in the
/// connection's temporary schema and is gone when the session ends.
/// </summary>
public sealed class LakeQuerySession : IDisposable
{
    private readonly DuckDBConnection _db;
    private readonly string _caseDirectory;
    private readonly IReadOnlyDictionary<string, string> _parameters;
    private readonly HashSet<string> _prepared = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _set = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="databasePath">The lake: &lt;case&gt;\_Lake\case.duckdb.</param>
    /// <param name="caseDirectory">The case folder, where a query's input files are looked for.</param>
    /// <param name="parameters">Values that replace the queries' defaults, by parameter name.</param>
    /// <param name="tempDirectory">Where DuckDB spills; the system's temporary folder when null.</param>
    public LakeQuerySession(string databasePath, string caseDirectory, IReadOnlyDictionary<string, string>? parameters = null,
        LakeOptions? options = null, string? tempDirectory = null)
    {
        if (!File.Exists(databasePath)) throw new FileNotFoundException($"No lake at {databasePath}", databasePath);
        _caseDirectory = caseDirectory;
        _parameters = parameters ?? new Dictionary<string, string>();
        _db = LakeDatabase.Open(databasePath, options ?? new LakeOptions(), tempDirectory ?? Path.GetTempPath(), readOnly: true);
    }

    /// <summary>Runs <paramref name="query"/> (and the setup it requires) and hands its rows to <paramref name="read"/>.</summary>
    public T Run<T>(LakeQuery query, Func<DbDataReader, T> read)
    {
        if (query.IsSetup) throw new InvalidOperationException($"{query.Name} is a setup query and returns no rows");
        Prepare(query);
        using var command = _db.CreateCommand();
        command.CommandText = query.Sql;
        using var reader = command.ExecuteReader();
        return read(reader);
    }

    /// <summary>Runs a query and writes its rows to <paramref name="csvPath"/>. Returns the row count.</summary>
    public long RunToCsv(LakeQuery query, string csvPath) => Run(query, reader => LakeCsv.Write(csvPath, reader));

    /// <summary>Runs a query and returns its rows as text cells, by column name.</summary>
    public List<Dictionary<string, string>> RunToRows(LakeQuery query) => Run(query, LakeCsv.ReadRows);

    /// <summary>Executes SQL on the session's connection, for temporary tables a caller fills.</summary>
    public void Execute(string sql) => LakeDatabase.Execute(_db, sql);

    /// <summary>The session's connection, for a caller that inserts rows with parameters.</summary>
    public DuckDBCommand CreateCommand() => _db.CreateCommand();

    private void Prepare(LakeQuery query)
    {
        foreach (var name in query.Requires)
        {
            if (_prepared.Contains(name)) continue;
            var setup = LakeQueryCatalogue.Find(name)
                        ?? throw new InvalidDataException($"Query {query.Name} requires {name}, which is not in the catalogue");
            Prepare(setup);
            Inputs(setup);
            LakeDatabase.Execute(_db, setup.Sql);
            _prepared.Add(name);
        }
        Inputs(query);
    }

    private void Inputs(LakeQuery query)
    {
        foreach (var parameter in query.Parameters)
        {
            if (!_set.Add(parameter.Name)) continue;
            var value = _parameters.TryGetValue(parameter.Name, out var given) ? given : parameter.Default;
            LakeDatabase.Execute(_db, $"SET VARIABLE {parameter.Name} = {LakeDatabase.Literal(value)}");
        }
        foreach (var table in query.Tables)
            if (_set.Add("table:" + table.Table)) StandIn(table);
        foreach (var input in query.Inputs)
            if (_set.Add("input:" + input.Table)) LoadInput(input);
    }

    /// <summary>
    /// An empty table for one the lake does not have, or a view that adds the columns an older
    /// tool did not write. Both are temporary, which DuckDB reads before the lake's own tables.
    /// </summary>
    private void StandIn(LakeQueryTable table)
    {
        var have = ColumnsOf(table.Table);
        var meta = new[] { "host VARCHAR", "source_id INTEGER", "row_no BIGINT" };
        if (have.Count == 0)
        {
            var columns = meta.Concat(table.Columns.Select(c => LakeDatabase.Identifier(c) + " VARCHAR"));
            LakeDatabase.Execute(_db, $"CREATE TEMP TABLE {LakeDatabase.Identifier(table.Table)} ({string.Join(", ", columns)})");
            return;
        }
        var missing = table.Columns.Where(c => !have.Contains(c)).ToList();
        if (missing.Count == 0) return;
        var added = string.Join(", ", missing.Select(c => "NULL::VARCHAR AS " + LakeDatabase.Identifier(c)));
        LakeDatabase.Execute(_db, $"CREATE TEMP VIEW {LakeDatabase.Identifier(table.Table)} AS " +
                                  $"SELECT *, {added} FROM main.{LakeDatabase.Identifier(table.Table)}");
    }

    /// <summary>
    /// Loads a case file into a temporary table with the declared columns, matched by name without
    /// regard to case or surrounding spaces; a column the file lacks is empty. The file's own
    /// header is kept in input_columns, so a caller can refuse a file that is not what it expects.
    /// </summary>
    private void LoadInput(LakeQueryInput input)
    {
        var path = Path.Combine(_caseDirectory, input.FileName);
        var table = LakeDatabase.Identifier(input.Table);
        var header = File.Exists(path) && new FileInfo(path).Length > 0 ? LakeCsv.ReadHeader(path) : null;
        if (header is null || header.Count == 0)
        {
            var empty = string.Join(", ", input.Columns.Select(c => LakeDatabase.Identifier(c) + " VARCHAR"));
            LakeDatabase.Execute(_db, $"CREATE TEMP TABLE {table} (input_row BIGINT, {empty})");
            return;
        }

        LakeDatabase.Execute(_db,
            $"CREATE TEMP TABLE input_load AS SELECT * FROM read_csv({LakeDatabase.Literal(path)}, header = false, " +
            "skip = 1, all_varchar = true, auto_detect = false, delim = ',', quote = '\"', escape = '\"', null_padding = true, strict_mode = false, " +
            $"columns = {{{string.Join(", ", header.Select((_, i) => $"'c{i}': 'VARCHAR'"))}}})");
        var select = input.Columns.Select(c =>
        {
            var at = header.FindIndex(h => h.Trim().Equals(c, StringComparison.OrdinalIgnoreCase));
            return (at < 0 ? "NULL::VARCHAR" : $"c{at}") + " AS " + LakeDatabase.Identifier(c);
        });
        LakeDatabase.Execute(_db, $"CREATE TEMP TABLE {table} AS SELECT rowid + 1 AS input_row, {string.Join(", ", select)} " +
                                  "FROM temp.input_load ORDER BY rowid; DROP TABLE temp.input_load");
        InputHeaders[input.Table] = header;
    }

    /// <summary>The header each loaded input file had, by table name; a missing or empty file has none.</summary>
    public Dictionary<string, List<string>> InputHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);

    private HashSet<string> ColumnsOf(string table)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT column_name FROM duckdb_columns() WHERE table_name = $table AND schema_name = 'main' " +
                              "AND database_name = current_database()";
        command.Parameters.Add(new DuckDBParameter("table", table));
        using var reader = command.ExecuteReader();
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read()) columns.Add(reader.GetString(0));
        return columns;
    }

    public void Dispose() => _db.Dispose();
}

/// <summary>
/// CSV as ArtefactForge writes it: UTF-8 with a byte order mark, every cell quoted, quotes
/// doubled, CRLF line ends. Written through a temporary file, so a reader never sees half of one.
/// </summary>
public static class LakeCsv
{
    public static void WriteRow(TextWriter writer, IEnumerable<string> cells)
    {
        var first = true;
        foreach (var cell in cells)
        {
            if (!first) writer.Write(',');
            first = false;
            writer.Write('"');
            writer.Write(cell.Replace("\"", "\"\""));
            writer.Write('"');
        }
        writer.Write("\r\n");
    }

    public static void Write(string path, IReadOnlyList<string> header, IEnumerable<IEnumerable<string>> rows)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temp = path + ".tmp";
        using (var writer = new StreamWriter(temp, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            WriteRow(writer, header);
            foreach (var row in rows) WriteRow(writer, row);
        }
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>Writes a query's rows. A text column is written as it is; anything else in an invariant form.</summary>
    public static long Write(string path, DbDataReader reader)
    {
        var header = Enumerable.Range(0, reader.FieldCount).Select(reader.GetName).ToList();
        long count = 0;
        Write(path, header, Rows());
        return count;

        IEnumerable<IEnumerable<string>> Rows()
        {
            while (reader.Read())
            {
                count++;
                yield return Enumerable.Range(0, reader.FieldCount).Select(i => Cell(reader, i)).ToList();
            }
        }
    }

    public static List<Dictionary<string, string>> ReadRows(DbDataReader reader)
    {
        var rows = new List<Dictionary<string, string>>();
        while (reader.Read())
        {
            var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = Cell(reader, i);
            rows.Add(row);
        }
        return rows;
    }

    public static string Cell(DbDataReader reader, int i)
    {
        if (reader.IsDBNull(i)) return "";
        return reader.GetValue(i) switch
        {
            string s => s,
            bool b => b ? "True" : "False",
            DateTime t => t.ToString(t.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd HH:mm:ss" : "yyyy-MM-dd HH:mm:ss.FFFFFFF",
                                     CultureInfo.InvariantCulture),
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            var v => v.ToString() ?? ""
        };
    }

    /// <summary>The first line of a CSV as cells (quoted or not), or null for an empty file.</summary>
    public static List<string>? ReadHeader(string path)
    {
        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var line = reader.ReadLine();
        if (line is null) return null;
        var cells = new List<string>();
        var cell = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { cell.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else cell.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { cells.Add(cell.ToString()); cell.Clear(); }
            else cell.Append(c);
        }
        cells.Add(cell.ToString());
        return cells;
    }
}

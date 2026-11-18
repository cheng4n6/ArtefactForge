using System.Globalization;
using DuckDB.NET.Data;

namespace ArtefactForge.Lake;

/// <summary>Opens lake databases with the settings every connection must have.</summary>
internal static class LakeDatabase
{
    /// <summary>
    /// Opens (creating if need be) the DuckDB file at <paramref name="path"/>. Every connection
    /// gets the same settings, then locks them so no SQL run later can change them:
    /// - no extension is downloaded or loaded on its own (ArtefactForge makes no network calls
    ///   unasked; the CSV reader is built into DuckDB);
    /// - memory and threads from <paramref name="options"/>, not DuckDB's 80% of RAM and every core;
    /// - spill files in <paramref name="tempDirectory"/>, on the case volume, not the system drive.
    /// </summary>
    public static DuckDBConnection Open(string path, LakeOptions options, string tempDirectory, bool readOnly = false)
    {
        var builder = new DuckDBConnectionStringBuilder { DataSource = path };
        // Read-only for queries: nothing a saved query does can change the lake.
        if (readOnly) builder["ACCESS_MODE"] = "READ_ONLY";
        var connection = new DuckDBConnection(builder.ConnectionString);
        try
        {
            connection.Open();
            var memoryMiB = Math.Max(64, options.EffectiveMemoryLimitBytes() / (1024 * 1024));
            Execute(connection, string.Join(";\n",
                "SET autoinstall_known_extensions = false",
                "SET autoload_known_extensions = false",
                "SET allow_community_extensions = false",
                $"SET memory_limit = '{memoryMiB.ToString(CultureInfo.InvariantCulture)}MiB'",
                $"SET threads = {options.EffectiveThreads().ToString(CultureInfo.InvariantCulture)}",
                $"SET temp_directory = {Literal(tempDirectory)}",
                // Rows keep the order of their file, so row_no is the row's place in the CSV.
                "SET preserve_insertion_order = true",
                // A time with an offset is read into UTC whatever zone the machine is in.
                "SET TimeZone = 'UTC'",
                "SET lock_configuration = true"));
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    public static void Execute(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    public static object? Scalar(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        var value = command.ExecuteScalar();
        return value is DBNull ? null : value;
    }

    public static long Count(DuckDBConnection connection, string sql) =>
        Convert.ToInt64(Scalar(connection, sql) ?? 0L, CultureInfo.InvariantCulture);

    /// <summary>A SQL string literal: single quotes doubled.</summary>
    public static string Literal(string text) => "'" + text.Replace("'", "''") + "'";

    /// <summary>A quoted SQL identifier: double quotes doubled.</summary>
    public static string Identifier(string name) => "\"" + name.Replace("\"", "\"\"") + "\"";
}

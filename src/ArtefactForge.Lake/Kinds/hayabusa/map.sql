-- Hayabusa csv-timeline: one row per rule hit. Every profile (minimal to super-verbose) has
-- Timestamp, RuleTitle, Level, Computer, Channel and EventID; the rest are read when the
-- profile wrote them. Timestamp carries its offset ("2026-09-15 08:12:57.190 +00:00", or ISO
-- 8601 with --ISO-8601) and is moved to UTC. Hayabusa's levels are spelled out.
SELECT
    lake_ts_offset(Timestamp)                               AS ts,
    Timestamp                                               AS ts_raw,
    'event'                                                 AS ts_desc,
    host,
    'windows'                                               AS platform,
    'hayabusa'                                              AS kind,
    'detection'                                             AS category,
    'alert'                                                 AS action,
    RuleTitle                                               AS rule_title,
    CASE lower(Level) WHEN 'crit' THEN 'critical' WHEN 'med' THEN 'medium' WHEN 'info' THEN 'informational'
                      ELSE lower(Level) END                 AS severity,
    TRY_CAST(EventID AS INTEGER)                            AS event_id,
    Channel                                                 AS channel,
    concat_ws(': ', RuleTitle, nullif(Details, ''))         AS summary,
    source_id,
    row_no
FROM raw_hayabusa
WHERE lake_ts_offset(Timestamp) IS NOT NULL

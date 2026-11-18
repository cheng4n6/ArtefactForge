-- Chainsaw hunt --csv: one CSV per rule group, each with timestamp, detections (the rule
-- titles) and path (the log) first and its own columns after; sigma.csv adds the event's
-- provider, ID and data. Chainsaw writes no level. The timestamp is ISO 8601 with an offset.
SELECT
    lake_ts_offset("timestamp")                             AS ts,
    "timestamp"                                             AS ts_raw,
    'event'                                                 AS ts_desc,
    host,
    'windows'                                               AS platform,
    'chainsaw'                                              AS kind,
    'detection'                                             AS category,
    'alert'                                                 AS action,
    detections                                              AS rule_title,
    TRY_CAST("Event ID" AS INTEGER)                         AS event_id,
    nullif("Event.System.Provider", '')                     AS provider,
    concat_ws(': ', detections, nullif(left("Event Data", 500), '')) AS summary,
    source_id,
    row_no
FROM raw_chainsaw
WHERE lake_ts_offset("timestamp") IS NOT NULL

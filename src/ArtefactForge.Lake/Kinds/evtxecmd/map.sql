-- EvtxECmd: one timeline row per event. Only fields EvtxECmd fills the same way for every event
-- are mapped; what the Maps put in PayloadData1-6 differs per event and stays in raw_evtxecmd,
-- except the target user, logon type and source address of logon events, which the standard
-- Security maps write as "Target: DOMAIN\user", "LogonType 3" and "WORKSTATION (10.0.0.5)".
-- A process start's parent comes from the Payload's EventData (version 2): ParentProcessName in
-- Security 4688, ParentImage in Sysmon 1. A Payload that is not JSON gives no parent.
WITH e AS (
    SELECT r.*,
           TRY_CAST(r.EventId AS INTEGER) AS eid,
           CASE WHEN r.Channel = 'Security'
                     AND TRY_CAST(r.EventId AS INTEGER) IN (4624, 4625, 4634, 4647, 4648, 4672)
                THEN nullif(regexp_extract(r.PayloadData1, '^Target: (.*)$', 1), '')
           END AS target_account
    FROM raw_evtxecmd r
),
m AS (
    SELECT e.*,
           coalesce(target_account, nullif(e.UserName, '')) AS account,
           -- The program of a command line: the quoted part, or up to the first space after
           -- something with an extension, or the whole value.
           coalesce(nullif(regexp_extract(e.ExecutableInfo, '^"([^"]+)"', 1), ''),
                    nullif(regexp_extract(e.ExecutableInfo, '^(\S.*?\.[A-Za-z0-9]{1,4})(\s|$)', 1), ''),
                    nullif(trim(e.ExecutableInfo), '')) AS image,
           CASE
               WHEN Channel = 'Security' AND eid IN (4624, 4625, 4634, 4647, 4648, 4672) THEN 'logon'
               WHEN Channel = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
                    AND eid IN (21, 22, 23, 24, 25) THEN 'logon'
               WHEN Channel = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
                    AND eid = 1149 THEN 'logon'
               WHEN Channel = 'Security' AND eid = 4688 THEN 'process'
               WHEN Channel = 'Microsoft-Windows-Sysmon/Operational' AND eid = 1 THEN 'process'
               WHEN Channel = 'Microsoft-Windows-Sysmon/Operational' AND eid = 3 THEN 'network'
               WHEN Channel = 'Security'
                    AND eid IN (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4756)
                    THEN 'account'
               WHEN (Channel = 'System' AND eid = 7045) OR (Channel = 'Security' AND eid = 4697)
                    THEN 'service'
               WHEN Channel = 'Microsoft-Windows-Windows Defender/Operational'
                    AND eid IN (1006, 1116, 1117) THEN 'detection'
               ELSE 'system'
           END AS cat
    FROM e
),
p AS (
    SELECT m.*,
           CASE WHEN m.cat = 'process' AND json_valid(m.Payload)
                     AND json_type(m.Payload, '$.EventData.Data') = 'ARRAY'
                THEN nullif(trim(json_extract_string(
                         list_filter(json_extract(m.Payload, '$.EventData.Data[*]'),
                                     d -> json_extract_string(d, '$."@Name"') IN ('ParentProcessName', 'ParentImage'))[1],
                         '$."#text"')), '')
           END AS parent_image
    FROM m
)
SELECT
    TRY_CAST(TimeCreated AS TIMESTAMP)                      AS ts,
    TimeCreated                                             AS ts_raw,
    'event'                                                 AS ts_desc,
    host,
    'windows'                                               AS platform,
    'evtxecmd'                                              AS kind,
    cat                                                     AS category,
    CASE
        WHEN Channel = 'Security' AND eid = 4624 THEN 'logon_success'
        WHEN Channel = 'Security' AND eid = 4625 THEN 'logon_fail'
        WHEN Channel = 'Security' AND eid IN (4634, 4647) THEN 'logoff'
        WHEN Channel = 'Security' AND eid = 4648 THEN 'logon_explicit'
        WHEN Channel = 'Security' AND eid = 4672 THEN 'logon_privileged'
        WHEN cat = 'process' THEN 'run'
        WHEN cat = 'service' THEN 'install'
        WHEN cat = 'network' THEN 'connect'
    END                                                     AS action,
    CASE WHEN contains(account, '\') THEN split_part(account, '\', 2) ELSE account END
                                                            AS user_name,
    nullif(UserId, '')                                      AS user_sid,
    CASE WHEN contains(account, '\') THEN split_part(account, '\', 1) END
                                                            AS user_domain,
    -- ExecutableInfo is the new process for a process start and the service's image for a
    -- service install; for other events it is the process that logged the event.
    CASE WHEN cat IN ('process', 'service') THEN image END  AS path,
    CASE WHEN cat IN ('process', 'service') THEN nullif(regexp_extract(image, '[^\\/]+$'), '') END
                                                            AS file_name,
    CASE WHEN cat IN ('process', 'service')
         THEN nullif(lower(regexp_extract(image, '(\.[^.\\/ ]{1,10})$', 1)), '')
    END                                                     AS extension,
    CASE WHEN cat IN ('process', 'service') THEN nullif(ExecutableInfo, '') END
                                                            AS command_line,
    CASE WHEN cat NOT IN ('process', 'service') THEN nullif(ExecutableInfo, '') END
                                                            AS process_path,
    TRY_CAST(ProcessId AS BIGINT)                           AS process_id,
    parent_image                                            AS parent_path,
    CASE WHEN cat = 'logon'
         THEN nullif(nullif(regexp_extract(RemoteHost, '\(([^)]*)\)\s*$', 1), '-'), '')
    END                                                     AS src_ip,
    eid                                                     AS event_id,
    Channel                                                 AS channel,
    Provider                                                AS provider,
    CASE WHEN cat = 'logon'
         THEN nullif(regexp_extract(PayloadData2, 'LogonType (\d+)', 1), '')
    END                                                     AS logon_type,
    concat_ws(': ', nullif(MapDescription, ''), nullif(PayloadData1, ''))
                                                            AS summary,
    source_id,
    row_no
FROM p
WHERE TRY_CAST(TimeCreated AS TIMESTAMP) IS NOT NULL

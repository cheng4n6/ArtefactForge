-- title: Data access: what the compromised users opened or browsed
-- category: data-access
-- severity: high
-- requires: data_access_prepare
-- description: The case's DataAccess.csv: the files and folders the accounts in
--   CompromisedUsers.csv opened, browsed or reached, on every host, sorted by time. The same thing
--   seen on two hosts (two collections of one machine) is one row. Artefact names the artefact
--   the row came from, for the analyst to check it against.
-- Each account seen in the activity once, against each listed user (a join, not a correlated
-- test: the name match's lambda cannot see a correlated column).
WITH accounts AS (
    SELECT DISTINCT user_name, sid FROM da_activity
),
matched AS (
    SELECT DISTINCT a.user_name, a.sid
    FROM accounts a CROSS JOIN da_compromised c
    WHERE da_matches(c.username, c.sid, a.user_name, a.sid)
),
listed AS (
    SELECT a.*, h.host_ord
    FROM da_activity a JOIN da_host h ON h.collection = a.host
    JOIN matched m ON m.user_name = a.user_name AND m.sid = a.sid
    QUALIFY row_number() OVER (PARTITION BY a.ts, upper(a.system), upper(a.user_name), upper(a.path), a.activity
                               ORDER BY h.host_ord, a.act_ord) = 1
)
SELECT da_fmt(ts) AS "Date/Time (UTC)", system AS "System", user_name AS "User", path AS "Path", activity AS "Activity",
       -- The kept row's artefact, as AccessRow.ArtefactFor names it: Security events by event ID,
       -- the Linux input by its file, the rest by the input's own name.
       CASE
           WHEN source = 'Security events (5140, 5145, 4663)' THEN
               CASE activity WHEN 'Share accessed' THEN 'Security 5140'
                             WHEN 'Accessed over share' THEN 'Security 5145'
                             ELSE 'Security 4663' END
           WHEN source = 'Linux recent files' THEN
               CASE activity WHEN 'Opened in vim' THEN '.viminfo' ELSE 'recently-used.xbel' END
           ELSE source
       END AS "Artefact"
FROM listed
ORDER BY ts, upper(system), upper(user_name), upper(path), host_ord, act_ord;

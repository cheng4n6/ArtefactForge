-- title: Data access: what the compromised users opened or browsed
-- category: data-access
-- severity: high
-- requires: data_access_prepare
-- description: The case's DataAccess.csv: the files and folders the accounts in
--   CompromisedUsers.csv opened, browsed or reached, on every host, sorted by time. The same thing
--   seen on two hosts (two collections of one machine) is one row.
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
SELECT da_fmt(ts) AS "Date/Time (UTC)", system AS "System", user_name AS "User", path AS "Path", activity AS "Activity"
FROM listed
ORDER BY ts, upper(system), upper(user_name), upper(path), host_ord, act_ord;

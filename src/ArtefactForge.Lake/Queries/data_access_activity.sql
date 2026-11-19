-- title: Data access: every account's file and folder activity per host
-- category: data-access
-- requires: data_access_prepare
-- description: Every host's Activity.csv: each dated time an account on the host opened, browsed
--   or reached a file or folder, every account's, in time order. Read only when
--   CompromisedUsers.csv lists someone. Collection says which host folder the row is for.
SELECT h.collection AS "Collection", da_fmt(a.ts) AS "TimeUtc", a.system AS "System", a.user_name AS "User",
       a.sid AS "SID", a.path AS "Path", a.activity AS "Activity", a.source AS "Source"
FROM da_activity a JOIN da_host h ON h.collection = a.host
WHERE EXISTS (SELECT 1 FROM da_compromised)
ORDER BY h.host_ord, a.act_ord;

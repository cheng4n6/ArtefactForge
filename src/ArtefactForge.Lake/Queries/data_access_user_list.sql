-- title: Data access: the case's accounts
-- category: data-access
-- requires: data_access_prepare
-- description: The case's UserList.csv: every host's accounts, host by host, to check the names
--   and SIDs in CompromisedUsers.csv against.
SELECT a.system AS "System", a.username AS "Username", a.sid AS "SID", a.profile_path AS "ProfilePath", a.source AS "Source"
FROM da_account a JOIN da_host h ON h.collection = a.host
ORDER BY h.host_ord, upper(a.system), upper(a.username), a.group_ord, a.sid_ord;

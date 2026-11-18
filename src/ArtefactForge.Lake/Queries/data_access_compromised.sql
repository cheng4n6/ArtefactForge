-- title: Data access: the compromised users
-- category: data-access
-- requires: data_access_prepare
-- description: The accounts in the analyst's CompromisedUsers.csv, a username, a SID or both per
--   row, in the file's order. With none listed, the data access queries report no activity.
SELECT username AS "Username", sid AS "SID"
FROM da_compromised
ORDER BY input_row;

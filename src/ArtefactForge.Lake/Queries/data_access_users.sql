-- title: Data access: each host's accounts
-- category: data-access
-- requires: data_access_prepare
-- description: Every host's Users.csv, one row per account: from ProfileList, the SAM, the
--   per-user output folders and passwd, with its SID and profile folder where any source gives
--   them. Collection says which host folder the row is for.
SELECT h.collection AS "Collection", a.system AS "System", a.username AS "Username", a.sid AS "SID",
       a.profile_path AS "ProfilePath", a.source AS "Source"
FROM da_account a JOIN da_host h ON h.collection = a.host
ORDER BY h.host_ord, upper(a.system), upper(a.username), a.group_ord, a.sid_ord;

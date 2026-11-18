-- title: Data access: working tables for the data access queries
-- category: data-access
-- type: setup
-- description: Reads each host's account sources (ProfileList, the SAM's accounts, the per-user
--   output folders, passwd) and its file and folder activity (LNK files, jump lists, ShellBags,
--   RecentDocs, OpenSavePidlMRU, Office File MRU, Security 5140, 5145 and 4663, Linux recent files)
--   into the temporary tables the data access queries share, with the analyst's
--   CompromisedUsers.csv. The same rules as ArtefactForge's DataAccess step, row for row.
-- input: compromised_users = CompromisedUsers.csv (Username, SID, Comment)
-- files: da_systeminfo = SystemInfo/SystemInfo.csv (Item, Value)
-- files: da_profilelist = Registry/*ProfileList*.csv (KeyName, ProfileImagePath)
-- files: da_sam = Registry/*UserAccounts*.csv (UserName, UserId)
-- files: da_passwd = Users/*passwd*.csv (Username, CanLogin, HomeDir)
-- files: da_lnk_recent = LNKFiles/**/*LECmd_Recent*.csv (LocalPath, NetworkPath, CommonPath, TargetIDAbsolutePath, SourceFile, SourceModified, SourceCreated)
-- files: da_lnk_office = LNKFiles/**/*LECmd_OfficeRecent*.csv (LocalPath, NetworkPath, CommonPath, TargetIDAbsolutePath, SourceFile, SourceModified, SourceCreated)
-- files: da_jumplists = JumpLists/**/*AutomaticDestinations*.csv (Path, LocalPath, LastModified, SourceFile)
-- files: da_shellbags = ShellBags/**/*SBECmd*.csv (AbsolutePath, FirstInteracted, LastInteracted, SourceFile)
-- files: da_recentdocs = Registry/**/*_RECmd_NTUSER_RecentDocs*.csv (TargetName, OpenedOn)
-- files: da_opensave = Registry/**/*_RECmd_NTUSER_OpenSavePidlMRU*.csv (AbsolutePath, OpenedOn)
-- files: da_officemru = Registry/**/*_RECmd_NTUSER_OfficeMRU*.csv (FileName, LastOpened)
-- files: da_evtx = EventLogs/**/EvtxECmd*.csv (TimeCreated, EventId, Channel, Computer, Keywords, Payload)
-- files: da_linux = UserFiles/**/*LinuxUserFiles_OtherHistory*.csv (Type, TimeUtc, Entry, User)

-- How each source is read, and why, is on ArtefactForge.Core's DataAccessReport and CaseUsers;
-- this is the same in SQL. Names compare without regard to case, as Windows does. Where the C#
-- keeps the first of several (a profile per SID, a row per key), the order it read them in is
-- kept here as an ordinal (ord, seq) and the lowest wins.

-- .NET's Trim(): Unicode white space, not only spaces as DuckDB's trim().
CREATE OR REPLACE TEMP MACRO da_trim(x) AS
    regexp_replace(coalesce(x, ''), '^[\t\n\v\f\r\x{85}\p{Z}]+|[\t\n\v\f\r\x{85}\p{Z}]+$', '', 'g');
-- A time as "yyyy-MM-dd HH:mm:ss", UTC: the whole cell (Linux), or its first 19 characters (the
-- EZ Tools' 100 ns digits dropped), as the C# ParseTime and ParseEventTime read them.
CREATE OR REPLACE TEMP MACRO da_exact_time(x) AS try_strptime(da_trim(x), '%Y-%m-%d %H:%M:%S');
CREATE OR REPLACE TEMP MACRO da_event_time(x) AS
    CASE WHEN length(coalesce(x, '')) >= 19 THEN da_exact_time(substr(x, 1, 19)) END;
CREATE OR REPLACE TEMP MACRO da_time(x) AS da_event_time(da_trim(x));
CREATE OR REPLACE TEMP MACRO da_fmt(t) AS strftime(t, '%Y-%m-%d %H:%M:%S');
-- The order Windows sorts paths in (OrdinalIgnoreCase), with '\' as the separator.
CREATE OR REPLACE TEMP MACRO da_path_order(p) AS upper(replace(p, '/', '\'));

-- A path as the client should read it, or NULL for something that is not a file or folder: a web
-- address, an app link (ms-teams:) or a shell namespace (::{GUID}). A shell path that reaches a
-- drive (Desktop\This PC\C:\Finance) starts at the drive. (CleanPath)
CREATE OR REPLACE TEMP MACRO da_clean_trimmed(t) AS
    CASE WHEN t = '' OR starts_with(t, '::') OR starts_with(lower(t), 'internet folder')
              OR regexp_matches(t, '^[A-Za-z][A-Za-z0-9+.\-]+:') THEN NULL
         WHEN regexp_matches(t, '(?:^|\\)[A-Za-z]:\\.*$') THEN regexp_extract(t, '(?:^|\\)([A-Za-z]:\\.*)$', 1)
         ELSE t END;
CREATE OR REPLACE TEMP MACRO da_clean_path(x) AS da_clean_trimmed(da_trim(x));
-- A folder a client cares about: on a drive or a share, or below a known folder. (IsFolderPath)
CREATE OR REPLACE TEMP MACRO da_is_folder(p) AS
    regexp_matches(p, '^[A-Za-z]:\\') OR starts_with(p, '\\')
    OR len(list_filter(string_split(p, '\'), s -> s <> '')) >= 3;
-- The profile a path is under: the part after the last "Users", when something follows it. (UserFromPath)
CREATE OR REPLACE TEMP MACRO da_parts_user(parts) AS
    CASE WHEN coalesce(list_position(list_reverse(list_transform(parts, s -> lower(s))), 'users'), 0) > 0
              AND len(parts) - list_position(list_reverse(list_transform(parts, s -> lower(s))), 'users') + 1 < len(parts) - 1
         THEN parts[len(parts) - list_position(list_reverse(list_transform(parts, s -> lower(s))), 'users') + 2]
         ELSE '' END;
CREATE OR REPLACE TEMP MACRO da_path_user(p) AS
    da_parts_user(list_filter(string_split_regex(coalesce(p, ''), '[\\/]'), s -> s <> ''));
-- Whose a per-user output file is: the profile folder it sits in (Category\User\file), or for a
-- file directly in its category, the name in front of the tool's marker. (UserFor)
CREATE OR REPLACE TEMP MACRO da_stem_user(stem, marker) AS
    CASE WHEN marker <> '' AND strpos(lower(stem), lower(marker)) > 1
         THEN substr(stem, 1, strpos(lower(stem), lower(marker)) - 1) ELSE '' END;
CREATE OR REPLACE TEMP MACRO da_file_user(path, marker) AS
    CASE WHEN len(string_split(path, '/')) >= 3 THEN string_split(path, '/')[2]
         ELSE da_stem_user(regexp_replace(string_split(path, '/')[-1], '\.[^.]*$', ''), marker) END;
-- A profile folder name against an output folder name: the output folder is the profile name with
-- the characters a file name cannot hold as '_'. (SameFolder)
CREATE OR REPLACE TEMP MACRO da_same_folder(profile_name, folder) AS
    lower(regexp_replace(profile_name, '[\x00-\x1F"<>|:*?\\/]', '_', 'g')) = lower(folder);

-- An account name without its domain, and the domain when given as DOMAIN\user. (Split)
CREATE OR REPLACE TEMP MACRO da_name_of(t) AS
    CASE WHEN contains(t, '\') THEN regexp_extract(t, '[^\\]*$')
         WHEN strpos(t, '@') > 1 THEN substr(t, 1, strpos(t, '@') - 1)
         ELSE t END;
CREATE OR REPLACE TEMP MACRO da_domain_of(t) AS
    CASE WHEN contains(t, '\') THEN regexp_extract(t, '^(.*)\\', 1) ELSE '' END;
-- The names, without the suffixes Windows adds to a second profile folder for one name
-- (user.000, user.CORP, user.CORP.001): each part after the wanted name is digits, capitals,
-- hyphens, or the wanted name's domain.
CREATE OR REPLACE TEMP MACRO da_names_match(w, d, c) AS
    CASE WHEN w = '' OR c = '' THEN false
         WHEN lower(w) = lower(c) THEN true
         WHEN length(c) > length(w) + 1 AND lower(substr(c, 1, length(w))) = lower(w) AND substr(c, length(w) + 1, 1) = '.'
         THEN list_bool_and(list_transform(string_split(substr(c, length(w) + 2), '.'),
                  s -> regexp_full_match(s, '[A-Z0-9-]+') OR (d <> '' AND lower(s) = lower(d))))
         ELSE false END;
-- Whether an account in the output is one of the compromised: by SID when both have one, so a
-- local and a domain admin are told apart, else by name. (CaseUsers.Matches)
CREATE OR REPLACE TEMP MACRO da_matches(wanted_name, wanted_sid, name, sid) AS
    CASE WHEN wanted_sid <> '' AND sid <> '' THEN lower(wanted_sid) = lower(sid)
         WHEN wanted_name = '' THEN false
         ELSE da_names_match(da_name_of(da_trim(wanted_name)), da_domain_of(da_trim(wanted_name)), da_name_of(da_trim(name))) END;

-- EvtxECmd's Payload: the EventData Name and #text pairs, last one of a name winning, as the C#
-- RemoteAccess.Fields reads them. Not JSON: none.
CREATE OR REPLACE TEMP MACRO da_payload_items(p) AS
    CASE WHEN p IS NOT NULL AND json_valid(p) THEN
         CASE json_type(p, '$.EventData.Data')
              WHEN 'ARRAY' THEN json_extract(p, '$.EventData.Data[*]')
              WHEN 'OBJECT' THEN [json_extract(p, '$.EventData.Data')] END END;
CREATE OR REPLACE TEMP MACRO da_field(items, field) AS
    list_extract(list_transform(
        list_filter(items, e -> json_type(e, '$."@Name"') = 'VARCHAR' AND lower(json_extract_string(e, '$."@Name"')) = lower(field)),
        e -> coalesce(json_extract_string(e, '$."#text"'), '')), -1);

-- --- the analyst's list -------------------------------------------------------------------------
CREATE OR REPLACE TEMP TABLE da_compromised AS
SELECT input_row, da_trim(Username) AS username, da_trim("SID") AS sid
FROM compromised_users
WHERE da_trim(Username) <> '' OR da_trim("SID") <> '';

-- --- hosts --------------------------------------------------------------------------------------
-- The machine's name from ArtefactForge's system summary (the last Hostname with a value), else
-- the folder, as the C# HostName.
CREATE OR REPLACE TEMP TABLE da_host AS
WITH named AS (
    SELECT host, arg_max("Value", row_no) AS hostname
    FROM da_systeminfo
    WHERE lower("Item") = 'hostname' AND coalesce("Value", '') <> ''
    GROUP BY host
)
SELECT h.host AS collection, coalesce(n.hostname, h.host) AS system,
       row_number() OVER (ORDER BY upper(h.host), h.host) AS host_ord
FROM hosts h LEFT JOIN named n ON n.host = h.host;

-- --- accounts -----------------------------------------------------------------------------------
-- ProfileList: a SID and a profile folder per person (S-1-5-21-...), the first of a SID kept.
CREATE OR REPLACE TEMP TABLE da_profile AS
WITH files AS (
    SELECT host, source_id, row_number() OVER (PARTITION BY host ORDER BY da_path_order(path), path) AS file_ord
    FROM da_profilelist_files
),
rows AS (
    SELECT r.host, da_trim(r.KeyName) AS sid, da_trim(r.ProfileImagePath) AS path,
           row_number() OVER (PARTITION BY r.host ORDER BY f.file_ord, r.row_no) AS ord
    FROM da_profilelist r JOIN files f ON f.source_id = r.source_id
)
SELECT host, sid, path, regexp_extract(rtrim(path, '\/'), '[^\\/]*$') AS name, ord
FROM rows
WHERE starts_with(upper(sid), 'S-1-5-21-') AND path <> ''
QUALIFY row_number() OVER (PARTITION BY host, lower(sid) ORDER BY ord) = 1;

-- The profile folders ArtefactForge wrote per-user output into, from the paths of the files in
-- them; templates and the shared folder are not accounts.
CREATE OR REPLACE TEMP TABLE da_user_folder AS
WITH parts AS (
    SELECT s.host, string_split(s.path, '/') AS p FROM sources s
),
folders AS (
    SELECT host, p[2] AS folder,
           list_position(['registry', 'lnkfiles', 'jumplists', 'shellbags', 'timeline', 'userfiles'], lower(p[1])) AS category
    FROM parts WHERE len(p) >= 3
)
SELECT host, arg_min(folder, (category, folder)) AS folder
FROM folders
WHERE category > 0 AND lower(folder) NOT IN ('default', 'default user', 'public', 'all users')
GROUP BY host, lower(folder);

-- A host's accounts in the order the C# gathers them: ProfileList, the SAM, the output folders,
-- passwd. The SAM holds the RID only; the SID is the profile's whose folder and RID agree.
CREATE OR REPLACE TEMP TABLE da_account_source AS
WITH sam_files AS (
    SELECT host, source_id, row_number() OVER (PARTITION BY host ORDER BY da_path_order(path), path) AS file_ord FROM da_sam_files
),
sam AS (
    SELECT r.host, da_trim(r.UserName) AS name, da_trim(r.UserId) AS rid,
           row_number() OVER (PARTITION BY r.host ORDER BY f.file_ord, r.row_no) AS ord
    FROM da_sam r JOIN sam_files f ON f.source_id = r.source_id
    WHERE da_trim(r.UserName) <> ''
),
passwd_files AS (
    SELECT host, source_id, row_number() OVER (PARTITION BY host ORDER BY da_path_order(path), path) AS file_ord FROM da_passwd_files
),
passwd AS (
    SELECT r.host, da_trim(r.Username) AS name, da_trim(r.HomeDir) AS home,
           row_number() OVER (PARTITION BY r.host ORDER BY f.file_ord, r.row_no) AS ord
    FROM da_passwd r JOIN passwd_files f ON f.source_id = r.source_id
    WHERE da_trim(r.Username) <> '' AND lower(da_trim(r.CanLogin)) = 'yes'
),
all_sources AS (
    SELECT host, 1 AS part, ord, name AS username, sid, path AS profile_path, 'ProfileList' AS source FROM da_profile
    UNION ALL
    SELECT s.host, 2, s.ord, s.name,
           coalesce((SELECT arg_min(p.sid, p.ord) FROM da_profile p
                     WHERE p.host = s.host AND lower(p.name) = lower(s.name) AND s.rid <> '' AND ends_with(p.sid, '-' || s.rid)), ''),
           '', 'SAM'
    FROM sam s
    UNION ALL
    SELECT u.host, 3, row_number() OVER (PARTITION BY u.host ORDER BY upper(u.folder), u.folder), u.folder,
           coalesce((SELECT arg_min(p.sid, p.ord) FROM da_profile p WHERE p.host = u.host AND da_same_folder(p.name, u.folder)), ''),
           '', 'Output folders'
    FROM da_user_folder u
    UNION ALL
    SELECT host, 4, ord, name, '', home, 'passwd' FROM passwd
)
SELECT a.host, h.system, a.username, a.sid, a.profile_path, a.source,
       row_number() OVER (PARTITION BY a.host ORDER BY a.part, a.ord) AS ord
FROM all_sources a JOIN da_host h ON h.collection = a.host;

-- One row per account (CaseUsers.Merge): a name's sources joined, its SID and profile path from
-- any of them; two SIDs for one name (a local and a domain admin) stay two rows.
CREATE OR REPLACE TEMP TABLE da_account AS
WITH grouped AS (
    SELECT *, upper(username) AS name_key, min(ord) OVER (PARTITION BY host, upper(username)) AS group_ord
    FROM da_account_source
),
sids AS (
    SELECT host, name_key, arg_min(sid, ord) AS sid, min(ord) AS sid_ord
    FROM grouped WHERE sid <> '' GROUP BY host, name_key, lower(sid)
),
entries AS (
    SELECT host, name_key, sid, sid_ord FROM sids
    UNION ALL
    SELECT DISTINCT host, name_key, '', 0 FROM grouped g
    WHERE NOT EXISTS (SELECT 1 FROM sids s WHERE s.host = g.host AND s.name_key = g.name_key)
),
members AS (
    SELECT e.host, e.name_key, e.sid AS entry_sid, e.sid_ord, g.* EXCLUDE (host, name_key)
    FROM entries e JOIN grouped g ON g.host = e.host AND g.name_key = e.name_key
                                 AND (g.sid = '' OR lower(g.sid) = lower(e.sid))
),
seen_by AS (
    SELECT host, name_key, entry_sid, arg_min(source, ord) AS source, min(ord) AS first_ord
    FROM members GROUP BY host, name_key, entry_sid, lower(source)
)
SELECT m.host, arg_min(m.system, m.ord) AS system, arg_min(m.username, m.ord) AS username, m.entry_sid AS sid,
       coalesce(arg_min(m.profile_path, m.ord) FILTER (WHERE m.profile_path <> ''), '') AS profile_path,
       (SELECT string_agg(s.source, '; ' ORDER BY s.first_ord) FROM seen_by s
        WHERE s.host = m.host AND s.name_key = m.name_key AND s.entry_sid = m.entry_sid) AS source,
       min(m.group_ord) AS group_ord, min(m.sid_ord) AS sid_ord
FROM members m
GROUP BY m.host, m.name_key, m.entry_sid;

-- --- file and folder activity -------------------------------------------------------------------
-- The inputs in the C# order, which is the order rows are kept in when two say the same thing.
CREATE OR REPLACE TEMP TABLE da_input AS
SELECT * FROM (VALUES
    (1, 'LNK (Recent)', 'LECmd_Recent', '_LECmd_Recent'),
    (2, 'LNK (Office Recent)', 'LECmd_OfficeRecent', '_LECmd_OfficeRecent'),
    (3, 'Jump lists', 'JLECmd', '_JLECmd'),
    (4, 'ShellBags', 'SBECmd', '_SBECmd'),
    (5, 'RecentDocs', 'RECmd_NTUSER', '_RECmd_NTUSER'),
    (6, 'OpenSavePidlMRU', 'RECmd_NTUSER', '_RECmd_NTUSER'),
    (7, 'Office File MRU', 'RECmd_NTUSER', '_RECmd_NTUSER'),
    (8, 'Security events (5140, 5145, 4663)', 'EvtxECmd', ''),
    (9, 'Linux recent files', 'LinuxUserFiles', '_LinuxUserFiles')
) AS t(input_ord, source, module, marker);

-- Every input file of every host. A module re-run writes beside the old EvtxECmd file
-- (EvtxECmd_EventLogs_2.csv); the newest is complete, so it alone is read.
CREATE OR REPLACE TEMP TABLE da_file AS
WITH listed AS (
    SELECT 1 AS input_ord, host, source_id, path, mtime FROM da_lnk_recent_files
    UNION ALL SELECT 2, host, source_id, path, mtime FROM da_lnk_office_files
    UNION ALL SELECT 3, host, source_id, path, mtime FROM da_jumplists_files
    UNION ALL SELECT 4, host, source_id, path, mtime FROM da_shellbags_files
    UNION ALL SELECT 5, host, source_id, path, mtime FROM da_recentdocs_files
    UNION ALL SELECT 6, host, source_id, path, mtime FROM da_opensave_files
    UNION ALL SELECT 7, host, source_id, path, mtime FROM da_officemru_files
    UNION ALL (SELECT 8, host, source_id, path, mtime FROM da_evtx_files
               QUALIFY row_number() OVER (PARTITION BY host ORDER BY mtime DESC NULLS LAST, da_path_order(path), path) = 1)
    UNION ALL SELECT 9, host, source_id, path, mtime FROM da_linux_files
)
SELECT l.input_ord, l.host, l.source_id, l.path,
       row_number() OVER (PARTITION BY l.host, l.input_ord ORDER BY da_path_order(l.path), l.path) AS file_ord,
       da_file_user(l.path, i.marker) AS folder_user
FROM listed l JOIN da_input i ON i.input_ord = l.input_ord;

-- One row per dated thing a reader of the C# step yields, before hosts' rows are merged: sub
-- orders the two a row can give (a shortcut's modified then created time, a folder's first then
-- last interaction).
CREATE OR REPLACE TEMP TABLE da_read AS
WITH lnk AS (
    SELECT source_id, row_no, da_path_user(SourceFile) AS row_user,
           da_clean_path(CASE WHEN coalesce(LocalPath, '') <> '' THEN LocalPath
                              WHEN coalesce(NetworkPath, '') <> ''
                                   AND rtrim(NetworkPath, '\') || CASE WHEN coalesce(CommonPath, '') <> '' THEN '\' || ltrim(CommonPath, '\') ELSE '' END <> ''
                              THEN rtrim(NetworkPath, '\') || CASE WHEN coalesce(CommonPath, '') <> '' THEN '\' || ltrim(CommonPath, '\') ELSE '' END
                              ELSE coalesce(TargetIDAbsolutePath, '') END) AS path,
           da_time(SourceModified) AS modified, da_time(SourceCreated) AS created
    FROM (SELECT * FROM da_lnk_recent UNION ALL SELECT * FROM da_lnk_office)
),
bags AS (
    SELECT source_id, row_no, da_path_user(SourceFile) AS row_user, da_clean_path(AbsolutePath) AS path,
           da_time(FirstInteracted) AS first_ts, da_time(LastInteracted) AS last_ts
    FROM da_shellbags
),
evtx AS (
    SELECT e.source_id, e.row_no, da_trim(e.EventId) AS id, da_event_time(e.TimeCreated) AS ts,
           split_part(da_trim(e.Computer), '.', 1) AS computer, da_payload_items(e.Payload) AS items
    FROM da_evtx e
    WHERE e.source_id IN (SELECT source_id FROM da_file WHERE input_ord = 8)
      AND lower(da_trim(e.Channel)) = 'security' AND da_trim(e.EventId) IN ('5140', '5145', '4663')
      AND NOT contains(lower(coalesce(e.Keywords, '')), 'failure')
),
events AS (
    SELECT source_id, row_no, id, ts, computer,
           coalesce(da_field(items, 'SubjectUserName'), '') AS account,
           coalesce(da_field(items, 'SubjectDomainName'), '') AS domain,
           coalesce(da_field(items, 'SubjectUserSid'), '') AS sid,
           coalesce(da_field(items, 'ObjectType'), 'File') AS object_type,
           coalesce(da_field(items, 'ObjectName'), '') AS object_name,
           coalesce(da_field(items, 'AccessList'), '') AS access_list,
           coalesce(da_field(items, 'ShareName'), '') AS share,
           ltrim(da_trim(da_field(items, 'RelativeTargetName')), '\') AS relative
    FROM evtx WHERE ts IS NOT NULL
),
users AS (
    SELECT *, CASE WHEN domain <> '' THEN domain || '\' || account ELSE account END AS row_user,
           CASE WHEN starts_with(share, '\\*\') AND computer <> '' THEN '\\' || computer || substr(share, 4) ELSE share END AS unc
    FROM events WHERE account <> '' AND NOT ends_with(account, '$')
),
linux AS (
    SELECT source_id, row_no, coalesce("User", '') AS row_user, da_exact_time(TimeUtc) AS ts,
           CASE "Type" WHEN 'recent file (desktop)' THEN 'Opened' WHEN 'vim file mark' THEN 'Opened in vim' END AS activity,
           CASE WHEN starts_with(lower(da_trim(Entry)), 'file://') THEN substr(da_trim(Entry), 8) ELSE da_trim(Entry) END AS entry
    FROM da_linux
)
SELECT source_id, row_no, 0 AS sub, modified AS ts, path, 'Opened' AS activity, row_user, '' AS row_sid
FROM lnk WHERE path IS NOT NULL AND modified IS NOT NULL
UNION ALL
SELECT source_id, row_no, 1, created, path, 'Opened', row_user, ''
FROM lnk WHERE path IS NOT NULL AND created IS NOT NULL AND (modified IS NULL OR created <= modified)
UNION ALL
SELECT source_id, row_no, 0, da_time(LastModified),
       da_clean_path(CASE WHEN coalesce("Path", '') <> '' THEN "Path" ELSE coalesce(LocalPath, '') END),
       'Opened', da_path_user(SourceFile), ''
FROM da_jumplists
WHERE da_clean_path(CASE WHEN coalesce("Path", '') <> '' THEN "Path" ELSE coalesce(LocalPath, '') END) IS NOT NULL
  AND da_time(LastModified) IS NOT NULL
UNION ALL
SELECT source_id, row_no, 0, first_ts, path, 'Folder browsed', row_user, ''
FROM bags WHERE path IS NOT NULL AND da_is_folder(path) AND first_ts IS NOT NULL
UNION ALL
SELECT source_id, row_no, 1, last_ts, path, 'Folder browsed', row_user, ''
FROM bags WHERE path IS NOT NULL AND da_is_folder(path) AND last_ts IS NOT NULL AND (first_ts IS NULL OR last_ts <> first_ts)
UNION ALL
-- RecentDocs keeps the file's name only, not its folder.
SELECT source_id, row_no, 0, da_time(OpenedOn), da_clean_path(TargetName), 'Opened', '', ''
FROM da_recentdocs WHERE da_clean_path(TargetName) IS NOT NULL AND da_time(OpenedOn) IS NOT NULL
UNION ALL
SELECT source_id, row_no, 0, da_time(OpenedOn), da_clean_path(AbsolutePath), 'Opened or saved via dialog', '', ''
FROM da_opensave WHERE da_clean_path(AbsolutePath) IS NOT NULL AND da_time(OpenedOn) IS NOT NULL
UNION ALL
SELECT source_id, row_no, 0, da_time(LastOpened), da_clean_path(FileName), 'Opened', '', ''
FROM da_officemru WHERE da_clean_path(FileName) IS NOT NULL AND da_time(LastOpened) IS NOT NULL
UNION ALL
-- 4663: a file read, written or deleted, strongest first by the rights used (%%1537 DELETE,
-- %%4417 WriteData, %%4418 AppendData, %%4416 ReadData).
SELECT source_id, row_no, 0, ts, da_clean_path(object_name),
       CASE WHEN contains(access_list, '%%1537') THEN 'Deleted (file audit)'
            WHEN contains(access_list, '%%4417') OR contains(access_list, '%%4418') THEN 'Written (file audit)'
            WHEN contains(access_list, '%%4416') THEN 'Read (file audit)'
            ELSE 'Accessed (file audit)' END,
       row_user, sid
FROM users
WHERE id = '4663' AND lower(object_type) = 'file' AND da_clean_path(object_name) IS NOT NULL
UNION ALL
-- 5140 and 5145: a share, or a file on it, reached over SMB. IPC$ is not data; \\*\Finance is
-- this host's own share, named by the event's Computer.
SELECT source_id, row_no, 0, ts,
       CASE WHEN id = '5145' AND relative <> '' THEN rtrim(unc, '\') || '\' || relative ELSE unc END,
       CASE WHEN id = '5145' THEN 'Accessed over share' ELSE 'Share accessed' END,
       row_user, sid
FROM users
WHERE id IN ('5140', '5145') AND share <> '' AND NOT ends_with(upper(share), 'IPC$')
UNION ALL
-- Smb://, sftp:// and the like are not local files; a vim mark without a time is left out.
SELECT source_id, row_no, 0, ts, entry, activity, row_user, ''
FROM linux WHERE activity IS NOT NULL AND ts IS NOT NULL AND (starts_with(entry, '/') OR starts_with(entry, '~'));

-- Each row with its host, account and SID: the profile folder the output sits in, else the
-- account the artefact names; the SID the artefact gives, else the profile's.
CREATE OR REPLACE TEMP TABLE da_row AS
WITH placed AS (
    SELECT f.host, f.input_ord, f.file_ord, r.row_no, r.sub, r.ts, r.path, r.activity, r.row_sid,
           CASE WHEN f.folder_user <> '' THEN f.folder_user ELSE r.row_user END AS who
    FROM da_read r JOIN da_file f ON f.source_id = r.source_id
),
who_sid AS (
    SELECT w.host, w.who, arg_min(p.sid, p.ord) AS sid
    FROM (SELECT DISTINCT host, who FROM placed) w
    JOIN da_profile p ON p.host = w.host AND da_same_folder(p.name, w.who)
    GROUP BY w.host, w.who
)
SELECT p.host, h.system, p.who AS user_name,
       CASE WHEN p.row_sid <> '' THEN p.row_sid ELSE coalesce(s.sid, '') END AS sid,
       p.ts, p.path, p.activity, i.source, p.input_ord,
       row_number() OVER (PARTITION BY p.host ORDER BY p.input_ord, p.file_ord, p.row_no, p.sub) AS seq
FROM placed p
JOIN da_host h ON h.collection = p.host
JOIN da_input i ON i.input_ord = p.input_ord
LEFT JOIN who_sid s ON s.host = p.host AND s.who = p.who;

-- A host's Activity.csv: two rows saying the same thing, from two artefacts, are one row, the
-- first read kept; then in time order.
CREATE OR REPLACE TEMP TABLE da_activity AS
SELECT host, system, user_name, sid, ts, path, activity, source,
       row_number() OVER (PARTITION BY host ORDER BY ts, seq) AS act_ord
FROM da_row
QUALIFY row_number() OVER (PARTITION BY host, ts, upper(system), upper(user_name), upper(path), activity ORDER BY seq) = 1;

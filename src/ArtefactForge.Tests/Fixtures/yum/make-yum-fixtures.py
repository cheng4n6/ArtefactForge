"""Builds the yum history fixtures in this folder. Development only.

Takes the schema from yum's own source rather than from memory: every CREATE statement in
yum/history.py, in the order yum runs them (the base tables in _create_db_file, then
_update_ops_2, then _update_ops_3). The older file is built with the base tables only, as a
history database from before trans_cmdline existed.

    git clone https://github.com/rpm-software-management/yum
    python3 make-yum-fixtures.py <yum>/yum/history.py

Writes to ./out/history; copy both files into the fixtures folder. Synthetic data, no evidence.
yum on RHEL 7 wrote 'TRUE' and 'FALSE' as text into trans_data_pkgs.done, so the rows do too.
"""
import os, re, sqlite3, sys

src = open(sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__)).read()
blocks = [b.replace('\\\n', '') for b in re.findall(r"'''\\\n(.*?)'''", src, re.S) if 'CREATE' in b]
# history.py lists _update_ops_3 (4), _update_ops_2 (8), then the base tables (8).
v3, v2, base = blocks[:4], blocks[4:12], blocks[12:]
assert base[0].lstrip().startswith('CREATE TABLE trans_beg') and v2[0].lstrip().startswith('CREATE TABLE trans_skip_pkgs') \
    and v3[0].lstrip().startswith('CREATE TABLE pkg_rpmdb'), 'history.py has changed shape'

def build(path, ops):
    if os.path.exists(path): os.remove(path)
    c = sqlite3.connect(path)
    c.execute('PRAGMA page_size=1024')
    for op in ops: c.execute(op)
    return c

def pkg(c, name, epoch, ver, rel, arch='x86_64'):
    c.execute('INSERT INTO pkgtups(name,arch,epoch,version,release,checksum) VALUES(?,?,?,?,?,?)',
              (name, arch, epoch, ver, rel, 'sha256:' + name))
    return c.execute('SELECT last_insert_rowid()').fetchone()[0]

def trans(c, begin, uid, rv_beg, rv_end, rc, items, cmdline=None):
    c.execute('INSERT INTO trans_beg(timestamp,rpmdb_version,loginuid) VALUES(?,?,?)', (begin, rv_beg, uid))
    tid = c.execute('SELECT last_insert_rowid()').fetchone()[0]
    for pid, state, done in items:
        c.execute('INSERT INTO trans_data_pkgs(tid,pkgtupid,done,state) VALUES(?,?,?,?)', (tid, pid, done, state))
    if cmdline is not None:
        c.execute('INSERT INTO trans_cmdline(tid,cmdline) VALUES(?,?)', (tid, cmdline))
    if rc is not None:
        c.execute('INSERT INTO trans_end(tid,timestamp,rpmdb_version,return_code) VALUES(?,?,?,?)', (tid, begin + 45, rv_end, rc))
    return tid

os.makedirs('out/history', exist_ok=True)

c = build('out/history/history-2024-03-01.sqlite', base + v2 + v3)
yumpkg = pkg(c, 'yum', '0', '3.4.3', '168.el7')
new_ssl = pkg(c, 'openssl', '1', '1.0.2k', '25.el7_9')
old_ssl = pkg(c, 'openssl', '1', '1.0.2k', '24.el7_9')
nmap = pkg(c, 'nmap', '2', '6.40', '19.el7')
ncat = pkg(c, 'nmap-ncat', '2', '6.40', '19.el7')
telnet = pkg(c, 'telnet', '1', '0.17', '66.el7')
socat = pkg(c, 'socat', '0', '1.7.3.2', '2.el7')

t1 = trans(c, 1709283600, 4294967295, '400:aaa', '401:bbb', 0,
           [(new_ssl, 'Update', 'TRUE'), (old_ssl, 'Updated', 'TRUE')], 'update -y openssl')
c.execute('INSERT INTO trans_with_pkgs(tid,pkgtupid) VALUES(?,?)', (t1, yumpkg))
# 402:ccc, not 401:bbb - the rpmdb changed between transactions 1 and 2 without yum.
t2 = trans(c, 1709370000, 1000, '402:ccc', '404:ddd', 0,
           [(nmap, 'Install', 'TRUE'), (ncat, 'Dep-Install', 'TRUE')], 'install -y nmap')
c.execute('INSERT INTO trans_script_stdout(tid,line) VALUES(?,?)', (t2, 'Created symlink for ncat.'))
t3 = trans(c, 1709456400, 1000, '404:ddd', '404:ddd', 1,
           [(telnet, 'Erase', 'FALSE')], 'erase -y telnet')
c.execute('INSERT INTO trans_error(tid,msg) VALUES(?,?)', (t3, 'Error in PREUN scriptlet in rpm package telnet'))
# No trans_end: yum was interrupted, which yum history shows as Aborted.
t4 = trans(c, 1709542800, 0, '404:ddd', None, None, [(socat, 'Install', 'FALSE')], 'install -y socat')
c.execute('INSERT INTO trans_skip_pkgs(tid,pkgtupid) VALUES(?,?)', (t4, telnet))
c.execute('INSERT INTO trans_rpmdb_problems(tid,problem,msg) VALUES(?,?,?)', (t4, 'duplicates', 'openssl is a duplicate'))
c.commit(); c.close()

# An older database, with the version 1 schema: no trans_cmdline or problem tables.
c = build('out/history/history-2019-06-01.sqlite', base)
wget = pkg(c, 'wget', '0', '1.14', '18.el7')
trans(c, 1559379600, 1001, '300:eee', '301:fff', 0, [(wget, 'Install', 'TRUE')])
c.commit(); c.close()
print('written to out/history')

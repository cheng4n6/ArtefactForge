"""Builds the dnf history.sqlite fixtures in this folder. Development only.

Uses libdnf's own schema files, so the fixtures have the real table layout including the 1.2 and
1.3 migrations (columns added by ALTER TABLE after the first transaction was written):

    git clone https://github.com/rpm-software-management/libdnf   (branch dnf-4-master)
    python3 make-dnf-fixtures.py <libdnf>/libdnf/transaction/sql

Writes to ./out; copy the three variants into the fixtures folder.
"""
import sys
LIBDNF = sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__)
import sqlite3, os, shutil
schema=open(os.path.join(LIBDNF,"create_tables.sql")).read().replace('R"**(','').replace(')**"','')
mig=[open(os.path.join(LIBDNF,f"migrate_tables_1_{v}.sql")).read().replace('R"**(','').replace(')**"','') for v in (2,3)]
def build(path, wal=False):
    c=sqlite3.connect(path); c.execute('PRAGMA page_size=1024')
    if wal: c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA wal_autocheckpoint=0')
    c.executescript(schema)
    c.execute("insert into repo values(1,'baseos'),(2,'@System'),(3,'epel')")
    def pkg(i,name,ver):
        c.execute('insert into item values(?,1)',(i,)); c.execute('insert into rpm values(?,?,?,?,?,?)',(i,name,0,ver,'1.el9','x86_64'))
    pkg(1,'nmap','7.92'); pkg(2,'socat','1.7.4'); pkg(3,'openssl','3.0.7'); pkg(4,'openssl','3.0.8'); pkg(5,'telnet','0.17')
    c.execute('insert into item values(6,2)'); c.execute("insert into comps_group values(6,'development','Development Tools','Development Tools',1)")
    def trans(begin,uid,cmd,items,state=1):
        c.execute('insert into trans(dt_begin,dt_end,rpmdb_version_begin,rpmdb_version_end,releasever,user_id,cmdline,state) values(?,?,?,?,?,?,?,?)',(begin,begin+30,'a','b','9',uid,cmd,state))
        t=c.execute('select last_insert_rowid()').fetchone()[0]
        for item,repo,action,reason in items: c.execute('insert into trans_item(trans_id,item_id,repo_id,action,reason,state) values(?,?,?,?,?,1)',(t,item,repo,action,reason))
        return t
    t1=trans(1704067200,4294967295,'dnf upgrade -y',[(4,1,6,2),(3,2,7,2)])
    for m in mig: c.executescript(m)
    t2=trans(1704153600,1000,'dnf install -y nmap socat '+'--setopt=x '*400,[(1,3,1,2),(2,3,1,1),(6,1,1,2)])
    c.execute('insert into console_output(trans_id,file_descriptor,line) values(?,1,?),(?,2,?)',(t2,'Installed: nmap',t2,'warning: scriptlet'))
    c.execute("update trans set comment='via ticket' where id=?",(t2,))
    c.commit()
    if wal:
        trans(1704240000,1001,'dnf remove -y telnet',[(5,2,8,2)]); c.commit()
    return c
os.makedirs('out', exist_ok=True)
c=build('out/history.sqlite'); c.close()
os.makedirs('wal', exist_ok=True)
c=build('wal/history.sqlite', wal=True)
os.makedirs('out/wal',exist_ok=True)
for s in ('','-wal'): shutil.copy('wal/history.sqlite'+s,'out/wal/history.sqlite'+s)
c.close()
# the same WAL cut short: the last transaction's commit frame is lost
os.makedirs('out/walcut',exist_ok=True)
shutil.copy('out/wal/history.sqlite','out/walcut/history.sqlite')
w=open('out/wal/history.sqlite-wal','rb').read(); open('out/walcut/history.sqlite-wal','wb').write(w[:-500])

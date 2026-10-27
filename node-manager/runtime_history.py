"""Disk indexes for cold ownership/version/accounting evidence; no history-sized RAM cache."""
from __future__ import annotations
from contextlib import contextmanager
import json,os,sqlite3
from pathlib import Path

def history_path():
    from singbox import manager
    return Path(os.environ.get('NODE_MANAGER_RUNTIME_STATE_DIR',str(manager.REGISTRY_PATH.parent/'runtime')))/'history.sqlite3'

@contextmanager
def database():
    path=history_path();path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    db=sqlite3.connect(path,timeout=15)
    try:
        if os.name!='nt':os.chmod(path,0o600)
        db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA journal_size_limit=8388608')
        db.execute('CREATE TABLE IF NOT EXISTS auth_owners(name TEXT PRIMARY KEY,user_id TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS user_versions(user_id TEXT PRIMARY KEY,version INTEGER NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS usage(user_id TEXT PRIMARY KEY,data TEXT NOT NULL)')
        db.execute("CREATE TABLE IF NOT EXISTS usage_totals(id INTEGER PRIMARY KEY,upload TEXT NOT NULL,download TEXT NOT NULL)")
        db.execute("INSERT OR IGNORE INTO usage_totals VALUES(1,'0','0')")
        with db:yield db
    finally:db.close()

def _lookup(db,table,column,names,value):
    result={};names=list(set(names))
    for offset in range(0,len(names),400):
        part=names[offset:offset+400]
        result.update(db.execute('SELECT '+column+','+value+' FROM '+table+' WHERE '+column+' IN ('+','.join('?' for _ in part)+')',part).fetchall())
    return result

def owners(names):
    names=list(names)
    if not names:return {}
    with database() as db:return _lookup(db,'auth_owners','name',names,'user_id')

def bind_owners(values):
    if not values:return
    with database() as db:
        db.executemany('INSERT OR IGNORE INTO auth_owners VALUES(?,?)',values.items())
        actual=_lookup(db,'auth_owners','name',values,'user_id')
        if any(actual[name]!=uid for name,uid in values.items()):
            from singbox.errors import SingboxConfigError
            raise SingboxConfigError('authentication name belongs to another historical user')

def versions(values):
    if not values:return
    with database() as db:
        db.executemany('INSERT INTO user_versions VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET version=MAX(version,excluded.version)',values.items())

def user_version(user_id,registry):
    active=registry.get('runtimeUserVersions',{}).get(user_id,0)
    with database() as db:row=db.execute('SELECT version FROM user_versions WHERE user_id=?',(user_id,)).fetchone()
    return max(active,row[0] if row else 0)

def archive_usage(values):
    if not values:return
    with database() as db:
        totals=list(map(int,db.execute('SELECT upload,download FROM usage_totals WHERE id=1').fetchone()))
        for user_id,data in values.items():
            old=db.execute('SELECT data FROM usage WHERE user_id=?',(user_id,)).fetchone()
            previous=json.loads(old[0]) if old else {}
            for index,key in enumerate(['upload','download']):totals[index]+=int(data.get(key) or 0)-int(previous.get(key) or 0)
            db.execute('INSERT INTO usage VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data',(user_id,json.dumps(data,separators=(',',':'))))
        db.execute('UPDATE usage_totals SET upload=?,download=? WHERE id=1',tuple(map(str,totals)))

def usage(user_ids):
    if not user_ids:return {}
    with database() as db:return {key:json.loads(value) for key,value in _lookup(db,'usage','user_id',user_ids,'data').items()}

def archived_totals(exclude):
    with database() as db:
        total=list(map(int,db.execute('SELECT upload,download FROM usage_totals WHERE id=1').fetchone()))
        for value in _lookup(db,'usage','user_id',exclude,'data').values():
            data=json.loads(value)
            for index,key in enumerate(['upload','download']):total[index]-=int(data.get(key) or 0)
        return total

def retire_epochs(values):
    if not values:return
    with database() as db:
        db.execute('CREATE TABLE IF NOT EXISTS retired_epochs(id TEXT PRIMARY KEY)')
        db.executemany('INSERT OR IGNORE INTO retired_epochs VALUES(?)',[(v,) for v in values])

def epoch_retired(value):
    with database() as db:
        db.execute('CREATE TABLE IF NOT EXISTS retired_epochs(id TEXT PRIMARY KEY)')
        return db.execute('SELECT 1 FROM retired_epochs WHERE id=?',(value,)).fetchone() is not None

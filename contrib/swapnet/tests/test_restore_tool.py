import json
import os
from pathlib import Path
import subprocess
import sys
from swapnet.journal import Journal
from swapnet.recovery import export_bundle
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault,atomic_private_write

TOOL=Path(__file__).resolve().parents[1]/'tools'/'restore_recovery.py'
NET='a'*64
PASSWORD='long restore tool fixture passphrase'

def bundle(tmp_path):
    os.chmod(tmp_path,0o700);folder=tmp_path/'live';folder.mkdir(mode=0o700)
    store=Store(folder/'state.sqlite');journal=Journal(store);key=os.urandom(32)
    atomic_private_write(folder/'vault.key',key);ForeignKeyVault(folder/'foreign-vault.json',key).save()
    out=export_bundle(journal,folder,PASSWORD,NET);store.close();return out['path']

def run(*args,stdin=PASSWORD+'\n'):
    return subprocess.run([sys.executable,str(TOOL),*args],input=stdin,capture_output=True,text=True,timeout=120)

def test_documented_restore_command(tmp_path):
    dest=tmp_path/'node'/'swapnet'
    r=run('--bundle',bundle(tmp_path),'--destination',str(dest),'--genesis',NET,'--confirm-node-stopped')
    assert r.returncode==0,r.stderr
    assert json.loads(r.stdout)=={'restored':True,'network':NET,'native_wallet_backup_also_required':True}
    assert sorted(p.name for p in dest.iterdir())==['foreign-vault.json','state.sqlite','vault.key']
    assert Journal(Store(dest/'state.sqlite')).setting('missing',1)==1

def test_restore_command_refuses_before_writing(tmp_path):
    b=bundle(tmp_path);dest=tmp_path/'node'/'swapnet'
    assert run('--bundle',b,'--destination',str(dest),'--genesis',NET).returncode!=0
    r=run('--bundle',b,'--destination',str(dest),'--genesis','b'*64,'--confirm-node-stopped')
    assert r.returncode==1 and 'GENESIS_MISMATCH' in r.stderr
    r=run('--bundle',b,'--destination',str(dest),'--genesis',NET,'--confirm-node-stopped',stdin='wrong but long enough passphrase\n')
    assert r.returncode==1 and 'BACKUP_AUTHENTICATION' in r.stderr
    assert not dest.exists() or not any(dest.iterdir())

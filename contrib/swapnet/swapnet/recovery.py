"""Encrypted consistent recovery bundles. No plaintext keys enter an RPC result.

The export contains the SQLite snapshot, foreign vault and its local wrapping key.
BTX wallet backup remains a separate native wallet operation; a SwapNet bundle
cannot recreate native PQ keys without that wallet. Restore is an offline action
and refuses a nonempty destination rather than merging financial state.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .vault import atomic_private_write
from .errors import require,SwapError

AAD=b'BTX/SWAPNET/RECOVERY/2'
MAX_BUNDLE=128*1024*1024

def _key(passphrase,salt):
    require(type(passphrase) is str and 20<=len(passphrase)<=1024,'BACKUP_PASSPHRASE','Use at least 20 characters for the encrypted recovery bundle')
    return Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(passphrase.encode())

def export_bundle(journal,directory,passphrase,network):
    directory=Path(directory);out=directory/'backups';out.mkdir(mode=0o700,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.snapshot-',dir=directory);os.close(fd)
    try:
        with journal.store.lock:
            target=sqlite3.connect(name)
            try:journal.store.db.backup(target)
            finally:target.close()
        paths={'state.sqlite':Path(name),'foreign-vault.json':directory/'foreign-vault.json','vault.key':directory/'vault.key'}
        files={}
        for filename,path in paths.items():
            require(path.is_file() and not path.is_symlink(),'BACKUP_SOURCE','Recovery component is missing or unsafe')
            data=path.read_bytes();require(len(data)<=MAX_BUNDLE//2,'BACKUP_LIMIT','Recovery component too large')
            files[filename]=base64.b64encode(data).decode()
        body={'version':2,'network':network,'audit_head':journal.store.verify_audit(),'files':files,'native_wallet_required':True}
        plaintext=json.dumps(body,separators=(',',':')).encode();require(len(plaintext)<=MAX_BUNDLE,'BACKUP_LIMIT','Recovery bundle too large')
        salt=os.urandom(16);nonce=os.urandom(12);cipher=AESGCM(_key(passphrase,salt)).encrypt(nonce,plaintext,AAD)
        envelope=json.dumps({'version':2,'salt':salt.hex(),'nonce':nonce.hex(),'ciphertext':base64.b64encode(cipher).decode()},separators=(',',':')).encode()
        filename='swapnet-recovery-'+hashlib.sha256(envelope).hexdigest()[:24]+'.snr'
        path=out/filename;atomic_private_write(path,envelope)
        journal.store.audit({'type':'recovery_exported','sha256':hashlib.sha256(envelope).hexdigest()})
        return {'path':str(path),'sha256':hashlib.sha256(envelope).hexdigest(),'encrypted':True,
                'native_wallet_backup_also_required':True,'secrets_in_rpc_result':False}
    finally:Path(name).unlink(missing_ok=True)

def restore_bundle(bundle,destination,passphrase,expected_network):
    source=Path(bundle);dest=Path(destination)
    require(source.is_file() and not source.is_symlink() and source.stat().st_size<=MAX_BUNDLE*2,'BACKUP_SOURCE','Invalid recovery bundle')
    require(not dest.is_symlink() and (not dest.exists() or not any(dest.iterdir())),'RESTORE_NONEMPTY','Restore requires an empty, offline data directory')
    try:
        env=json.loads(source.read_bytes());require(set(env)=={'version','salt','nonce','ciphertext'} and env['version']==2,'BACKUP_VERSION','Unsupported recovery format')
        salt=bytes.fromhex(env['salt']);nonce=bytes.fromhex(env['nonce']);require(len(salt)==16 and len(nonce)==12,'BACKUP_FORMAT','Invalid encryption parameters')
        plain=AESGCM(_key(passphrase,salt)).decrypt(nonce,base64.b64decode(env['ciphertext'],validate=True),AAD)
        require(len(plain)<=MAX_BUNDLE,'BACKUP_LIMIT','Decrypted bundle too large');body=json.loads(plain)
    except SwapError:raise
    except Exception as e:raise SwapError('BACKUP_AUTHENTICATION','Recovery bundle authentication failed') from e
    require(body.get('network')==expected_network,'GENESIS_MISMATCH','Recovery bundle belongs to another network')
    require(set(body['files'])=={'state.sqlite','foreign-vault.json','vault.key'},'BACKUP_FORMAT','Unexpected file set')
    # Validate all bytes and DB before publishing any destination content.
    decoded={k:base64.b64decode(v,validate=True) for k,v in body['files'].items()}
    require(len(decoded['vault.key'])==32,'BACKUP_FORMAT','Invalid local vault wrapping key')
    dest.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.swapnet-restore-',dir=dest.parent) as temp:
        stage=Path(temp);os.chmod(stage,0o700)
        for name,data in decoded.items():atomic_private_write(stage/name,data)
        from .store import Store
        from .vault import ForeignKeyVault
        db=Store(stage/'state.sqlite')
        try:
            require(db.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok','DATABASE_CORRUPT','SQLite integrity check failed')
            require(db.verify_audit()==body['audit_head'],'AUDIT_CORRUPT','Audit head mismatch')
            ForeignKeyVault(stage/'foreign-vault.json',decoded['vault.key'])
            # Persist the restore boundary before any runnable destination is published.
            from .journal import Journal
            journal = Journal(db)
            for (sid,) in db.db.execute('SELECT id FROM sn_negotiations').fetchall():
                journal.set_setting('restored_session:'+sid, True)
        finally:db.close()
        dest.mkdir(mode=0o700,exist_ok=True)
        for name in decoded:atomic_private_write(dest/name,(stage/name).read_bytes())
    return {'restored':True,'network':expected_network,'native_wallet_backup_also_required':True}

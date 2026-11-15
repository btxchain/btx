"""Realm-encrypted, bounded, resumable content-addressed storage.

SHA-384 binds plaintext pieces; realm HMACs hide cross-realm equality in paths.
AES-256-GCM protects local disks. Transfers use independently authenticated TLS.
A verified digest is an integrity assertion, never evidence that compute was honest.
"""
import contextlib
import hashlib
import hmac
import io
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .codec import encode, decode, byte_id, fixed_id, fields, integer
from .storage import Database, private_dir, atomic_write
from .errors import MeshError, require

PIECE_BYTES = 4 * 1024 * 1024
MAX_PIECES = 16384


class BlobStore:
    def __init__(self,path:Path,quota_bytes:int=32*1024**3):
        self.root=private_dir(Path(path));self.keydir=private_dir(self.root/"keys")
        self.objects=private_dir(self.root/"pieces");self.quota=quota_bytes
        self.db=Database(self.root/"store.sqlite3")
        self.db.db.executescript("""
        CREATE TABLE IF NOT EXISTS piece(realm TEXT,digest TEXT,size INTEGER,access_ms INTEGER,pins INTEGER DEFAULT 0,transfers INTEGER DEFAULT 0,PRIMARY KEY(realm,digest));
        CREATE TABLE IF NOT EXISTS artifact(realm TEXT,digest TEXT,manifest TEXT,verified INTEGER,PRIMARY KEY(realm,digest));
        CREATE INDEX IF NOT EXISTS piece_evict ON piece(pins,transfers,access_ms);
        """)
        # This store process exclusively owns the store directory. A daemon restart
        # has closed its transfer streams; references from other processes are not supported.
        self.db.db.execute("UPDATE piece SET transfers=0")
    def provision_realm(self,realm:str,key:bytes|None=None):
        fixed_id(realm);p=self.keydir/realm
        if p.exists():
            existing=p.read_bytes();require(len(existing)==32,"REALM_KEY")
            require(key is None or hmac.compare_digest(existing,key),"KEY_REPLACEMENT_FORBIDDEN")
            return
        if key is None:key=os.urandom(32)
        require(len(key)==32,"REALM_KEY");atomic_write(p,key)
    def key(self,realm):
        fixed_id(realm);p=self.keydir/realm
        require(p.exists() and not p.is_symlink(),"REALM_UNAVAILABLE")
        key=p.read_bytes();require(len(key)==32,"REALM_KEY");return key
    def path(self,realm,id):
        fixed_id(id)
        name=hmac.new(self.key(realm),b"BTX/PiecePath/1\x00"+bytes.fromhex(id),hashlib.sha384).hexdigest()
        return self.objects/realm/name[:2]/name
    def prefix_key(self,realm,fingerprint,tokens):
        return hmac.new(self.key(realm),b"BTX/PrivatePrefix/1\x00"+encode({"fingerprint":fingerprint,"tokens":tokens}),hashlib.sha384).hexdigest()
    def usage(self,c=None):return (c or self.db.db).execute("SELECT COALESCE(SUM(size+28),0) FROM piece").fetchone()[0]
    def eviction_plan(self,c,need,exclude=None):
        """Plan first: a quota failure must never delete a still-indexed file."""
        excess=self.usage(c)+need-self.quota
        if excess<=0:return []
        rows=c.execute("SELECT realm,digest,size FROM piece WHERE pins=0 AND transfers=0 ORDER BY access_ms,realm,digest").fetchall()
        selected=[];freed=0
        for realm,id,size in rows:
            if exclude==(realm,id):continue
            selected.append((realm,id,self.path(realm,id)));freed+=size+28
            if freed>=excess:return selected
        raise MeshError("STORAGE_QUOTA","pinned or leased data prevents reclamation")
    def put_piece(self,realm,data:bytes,expected=None):
        require(len(data)<=PIECE_BYTES,"PIECE_LIMIT")
        id=byte_id(data);require(expected is None or id==expected,"PIECE_DIGEST")
        key=self.key(realm);path=self.path(realm,id);evicted=[]
        with self.db.tx() as c:
            row=c.execute("SELECT size,pins,transfers FROM piece WHERE realm=? AND digest=?",(realm,id)).fetchone()
            aad=b"BTX/EncryptedPiece/1\x00"+bytes.fromhex(realm)+bytes.fromhex(id)
            if row and path.exists():
                require(row[0]==len(data),"PIECE_SIZE")
                raw=path.read_bytes()
                try:
                    if AESGCM(key).decrypt(raw[:12],raw[12:],aad)==data:return id
                except (InvalidTag,ValueError):pass
                # Re-upload of known correct bytes repairs a corrupted replica.
            need=0 if row else len(data)+28
            evicted=self.eviction_plan(c,need,exclude=(realm,id))
            nonce=os.urandom(12)
            # Allow at most one piece of transient staging headroom. Publish bytes
            # before metadata; a crash may leave an unindexed orphan, not a false hit.
            atomic_write(path,nonce+AESGCM(key).encrypt(nonce,data,aad))
            for old_realm,old_id,_ in evicted:
                c.execute("DELETE FROM piece WHERE realm=? AND digest=?",(old_realm,old_id))
                c.execute("UPDATE artifact SET verified=0 WHERE realm=?",(old_realm,))
            c.execute("INSERT OR REPLACE INTO piece VALUES(?,?,?,?,?,?)",(realm,id,len(data),int(time.time()*1000),row[1] if row else 0,row[2] if row else 0))
        # A failed SQL commit never removes an old file. A successful commit
        # makes evicted files inaccessible before their physical deletion.
        for _,_,old_path in evicted:
            with contextlib.suppress(FileNotFoundError):old_path.unlink()
        return id
    @contextlib.contextmanager
    def lease_piece(self,realm,id):
        path=self.path(realm,id)
        with self.db.tx() as c:
            row=c.execute("SELECT size FROM piece WHERE realm=? AND digest=?",(realm,id)).fetchone()
            require(row is not None and path.exists(),"CACHE_MISS")
            c.execute("UPDATE piece SET transfers=transfers+1,access_ms=? WHERE realm=? AND digest=?",(int(time.time()*1000),realm,id))
        try:
            raw=path.read_bytes();require(28<=len(raw)<=PIECE_BYTES+28,"PIECE_SIZE")
            aad=b"BTX/EncryptedPiece/1\x00"+bytes.fromhex(realm)+bytes.fromhex(id)
            try:data=AESGCM(self.key(realm)).decrypt(raw[:12],raw[12:],aad)
            except InvalidTag as e:raise MeshError("PIECE_AUTH") from e
            require(byte_id(data)==id,"PIECE_DIGEST")
            yield data
        finally:
            with self.db.tx() as c:c.execute("UPDATE piece SET transfers=MAX(0,transfers-1) WHERE realm=? AND digest=?",(realm,id))
    def read_piece(self,realm,id):
        with self.lease_piece(realm,id) as data:return data
    def put_stream(self,realm,stream,max_bytes=64*1024**3):
        self.key(realm);parts=[];sha=hashlib.sha384();size=0
        # Protect partial output against eviction by subsequent pieces in this upload.
        pinned=[]
        try:
            while True:
                data=stream.read(PIECE_BYTES)
                if not data:break
                size+=len(data);require(size<=max_bytes and len(parts)<MAX_PIECES,"ARTIFACT_LIMIT")
                sha.update(data);id=self.put_piece(realm,data)
                with self.db.tx() as c:c.execute("UPDATE piece SET pins=pins+1 WHERE realm=? AND digest=?",(realm,id))
                pinned.append(id);parts.append({"digest":id,"bytes":len(data)})
            artifact=sha.hexdigest()
            manifest={"version":1,"artifact":artifact,"bytes":size,"pieces":parts}
            with self.db.tx() as c:c.execute("INSERT OR REPLACE INTO artifact VALUES(?,?,?,1)",(realm,artifact,encode(manifest,4*1024*1024).decode()))
            return manifest
        finally:
            with self.db.tx() as c:
                for id in pinned:c.execute("UPDATE piece SET pins=MAX(0,pins-1) WHERE realm=? AND digest=?",(realm,id))
    def put_bytes(self,realm,data):return self.put_stream(realm,io.BytesIO(data),max_bytes=len(data))
    def manifest(self,realm,id):
        self.key(realm);fixed_id(id)
        row=self.db.db.execute("SELECT manifest FROM artifact WHERE realm=? AND digest=?",(realm,id)).fetchone()
        require(row is not None,"CACHE_MISS")
        return decode(row[0].encode(),4*1024*1024)
    def accept_manifest(self,realm,m):
        self.key(realm);fields(m,{"version","artifact","bytes","pieces"})
        require(m["version"]==1,"MANIFEST_VERSION");fixed_id(m["artifact"])
        integer(m["bytes"],0,MAX_PIECES*PIECE_BYTES)
        require(isinstance(m["pieces"],list) and len(m["pieces"])<=MAX_PIECES,"PIECE_COUNT")
        total=0
        for i,p in enumerate(m["pieces"]):
            fields(p,{"digest","bytes"});fixed_id(p["digest"]);integer(p["bytes"],1,PIECE_BYTES)
            if i<len(m["pieces"])-1:require(p["bytes"]==PIECE_BYTES,"PIECE_GEOMETRY")
            total+=p["bytes"]
        require(total==m["bytes"],"MANIFEST_SIZE")
        with self.db.tx() as c:c.execute("INSERT OR REPLACE INTO artifact VALUES(?,?,?,0)",(realm,m["artifact"],encode(m,4*1024*1024).decode()))
    def missing(self,realm,m):
        return [p for p in m["pieces"] if not self.db.db.execute("SELECT 1 FROM piece WHERE realm=? AND digest=?",(realm,p["digest"])).fetchone()]
    def stream(self,realm,id):
        m=self.manifest(realm,id);sha=hashlib.sha384();size=0
        for p in m["pieces"]:
            with self.lease_piece(realm,p["digest"]) as data:
                require(len(data)==p["bytes"],"PIECE_SIZE");sha.update(data);size+=len(data);yield data
        require(size==m["bytes"] and sha.hexdigest()==id,"ARTIFACT_DIGEST")
        with self.db.tx() as c:c.execute("UPDATE artifact SET verified=1 WHERE realm=? AND digest=?",(realm,id))
    def read_bytes(self,realm,id,max_bytes=256*1024*1024):
        require(self.manifest(realm,id)["bytes"]<=max_bytes,"READ_LIMIT")
        return b"".join(self.stream(realm,id))
    def export_file(self,realm,id,path):
        # Stream to a staging file; never expose partially verified tensor files.
        import tempfile
        path=Path(path);private_dir(path.parent);require(not path.is_symlink(),"SYMLINK")
        fd,tmp=tempfile.mkstemp(dir=path.parent,prefix=".verified-")
        try:
            with os.fdopen(fd,"wb") as f:
                for data in self.stream(realm,id):f.write(data)
                f.flush();os.fsync(f.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    def pin(self,realm,id,delta):
        require(delta in (-1,1),"PIN_DELTA")
        m=self.manifest(realm,id)
        with self.db.tx() as c:
            for p in m["pieces"]:
                require(c.execute("SELECT 1 FROM piece WHERE realm=? AND digest=?",(realm,p["digest"])).fetchone() is not None,"CACHE_MISS")
                c.execute("UPDATE piece SET pins=MAX(0,pins+?) WHERE realm=? AND digest=?",(delta,realm,p["digest"]))
    def retire_realm(self,realm):
        # New reads fail. This is key removal, NOT a proof of SSD/RAM secure erasure.
        p=self.keydir/fixed_id(realm)
        if p.exists():p.unlink()
        return {"new_access":False,"physical_secure_erase_proven":False}
    def close(self):self.db.close()

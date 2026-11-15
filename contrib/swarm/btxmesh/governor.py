"""Device-wide resource leases across all joined realms.

Logical expiry does not prove that a GPU transfer/process stopped. Resource
release requires the managed child to exit. Crash recovery verifies a Linux
process birth stamp before touching a PID; ambiguous reservations remain held.
Host bytes stay charged until that same update frees the accounting slot.
"""
import os
import time
from pathlib import Path
from .codec import decode,integer
from .storage import Database
from .errors import require

# Same default as the workload check. A policy that omits host_bytes uses it.
DEFAULT_HOST_BYTES=2*1024**3
_CHARGED=("ACTIVE","CANCELLING")


def process_birth(pid):
    try:
        text=Path(f"/proc/{pid}/stat").read_text()
        return text[text.rfind(")")+2:].split()[19]
    except (OSError,IndexError):return None


class Governor:
    def __init__(self,data:Path):
        self.data=Path(data);self.db=Database(self.data/"resources.sqlite3")
        self.db.db.execute("CREATE TABLE IF NOT EXISTS resource_lease(id TEXT PRIMARY KEY,realm TEXT,owner_pid INTEGER,child_pid INTEGER,birth TEXT,slots INTEGER,vram INTEGER,host_bytes INTEGER NOT NULL DEFAULT 0,state TEXT)")
        cols=[row[1] for row in self.db.db.execute("PRAGMA table_info(resource_lease)")]
        if "host_bytes" not in cols:self.db.db.execute("ALTER TABLE resource_lease ADD COLUMN host_bytes INTEGER NOT NULL DEFAULT 0")
    def policy(self):return decode((self.data/"config.json").read_bytes())["resource_policy"]
    def host_ceiling(self):
        p=self.policy()
        if "host_bytes" not in p:return DEFAULT_HOST_BYTES
        return integer(p["host_bytes"],1,2**62,"HOST_BUDGET")
    def acquire(self,id,realm,vram=0,host_bytes=0):
        p=self.policy();ceiling=self.host_ceiling()
        integer(host_bytes,0,2**62,"HOST_BUDGET")
        require(p["idle_contribution"] is True,"COMPUTE_NOT_AUTHORIZED")
        with self.db.tx() as c:
            rows=c.execute("SELECT slots,vram,host_bytes FROM resource_lease WHERE state IN ('ACTIVE','CANCELLING')").fetchall()
            require(sum(r[0] for r in rows)+1<=p["slots"],"DEVICE_SLOTS")
            require(sum(r[1] for r in rows)+vram<=p["vram_bytes"],"DEVICE_VRAM")
            require(sum((r[2] or 0) for r in rows)+host_bytes<=ceiling,"DEVICE_HOST")
            c.execute("INSERT INTO resource_lease(id,realm,owner_pid,child_pid,birth,slots,vram,host_bytes,state) VALUES(?,?,?,?,?,?,?,?,?)",(id,realm,os.getpid(),0,"",1,vram,host_bytes,"ACTIVE"))
        return p
    def started(self,id,pid):
        with self.db.tx() as c:c.execute("UPDATE resource_lease SET child_pid=?,birth=? WHERE id=? AND state='ACTIVE'",(pid,process_birth(pid) or "UNKNOWN",id))
    def cancel(self,id):
        # Cancellation does not return host bytes. The slot is still charged.
        with self.db.tx() as c:
            row=c.execute("SELECT state FROM resource_lease WHERE id=?",(id,)).fetchone()
            require(row is not None and row["state"]=="ACTIVE","LEASE_STATE")
            c.execute("UPDATE resource_lease SET state='CANCELLING' WHERE id=?",(id,))
    def release(self,id,*,quiescent):
        require(quiescent,"PHYSICAL_QUIESCENCE_REQUIRED")
        with self.db.tx() as c:
            row=c.execute("SELECT state FROM resource_lease WHERE id=?",(id,)).fetchone()
            require(row is not None,"LEASE_STATE")
            if row["state"]=="QUIESCENT":return
            require(row["state"] in _CHARGED,"LEASE_STATE")
            # Slot and host reservation leave in this update, not at cancellation.
            c.execute("UPDATE resource_lease SET state='QUIESCENT' WHERE id=?",(id,))
    def reconcile(self):
        released=[];ambiguous=[]
        with self.db.tx() as c:
            for r in c.execute("SELECT * FROM resource_lease WHERE state IN ('ACTIVE','CANCELLING')").fetchall():
                if r["child_pid"]==0:
                    # Owner may still be between reservation and spawn.
                    try:os.kill(r["owner_pid"],0);alive=True
                    except ProcessLookupError:alive=False
                    except PermissionError:alive=True
                    if alive:ambiguous.append(r["id"]);continue
                else:
                    birth=process_birth(r["child_pid"])
                    if birth==r["birth"] or (birth is None and r["birth"]=="UNKNOWN"):
                        ambiguous.append(r["id"]);continue
                c.execute("UPDATE resource_lease SET state='QUIESCENT' WHERE id=?",(r["id"],));released.append(r["id"])
        return {"released":released,"ambiguous_still_charged":ambiguous}
    def close(self):self.db.close()

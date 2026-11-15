"""Signed bounded LAN discovery, persistent model subscriptions, small-world peers.

Discovery is not authority. Unpinned public cards can supply metadata but cannot
become voters, disclose a private cache, execute work, or acquire wallet access.
"""
import asyncio
import hashlib
import json
import os
import socket
import time
from pathlib import Path
from .codec import encode,decode,digest,fixed_id,fields
from .identity import verify,verify_envelope
from .errors import MeshError,require
from .storage import Database

MULTICAST="239.255.42.35"
PORT=29449
MAX_CARD=12000


class DiscoveryBook:
    def __init__(self,db:Database,pinned:dict):
        self.db=db;self.pinned=pinned
        db.db.executescript("""
        CREATE TABLE IF NOT EXISTS discovery(peer TEXT PRIMARY KEY,body TEXT,expires_ms INTEGER);
        CREATE TABLE IF NOT EXISTS subscriptions(artifact TEXT PRIMARY KEY,lineage TEXT,body TEXT,updated_ms INTEGER);
        """)
    def accept(self,card,now_ms=None):
        fields(card,{"public_key","envelope"})
        require(len(encode(card,MAX_CARD))<=MAX_CARD,"CARD_LIMIT")
        b=card["envelope"]["body"];sender=b["sender"]
        verified=verify_envelope(card["envelope"],{sender:card["public_key"]},now_ms)
        p=verified["payload"]
        fields(p,{"kind","peer","endpoint","lineages","protocols"})
        require(p["kind"]=="presence" and p["peer"]==sender,"CARD_IDENTITY")
        require(isinstance(p["lineages"],list) and len(p["lineages"])<=16,"CARD_LINEAGES")
        for id in p["lineages"]:fixed_id(id)
        require(isinstance(p["endpoint"],str) and len(p["endpoint"])<=512,"ENDPOINT")
        now_ms=now_ms if now_ms is not None else int(time.time()*1000)
        with self.db.tx() as c:
            c.execute("DELETE FROM discovery WHERE expires_ms<=?",(now_ms,))
            n=c.execute("SELECT COUNT(*) FROM discovery").fetchone()[0]
            require(n<1024 or c.execute("SELECT 1 FROM discovery WHERE peer=?",(sender,)).fetchone(),"DISCOVERY_QUOTA")
            c.execute("INSERT OR REPLACE INTO discovery VALUES(?,?,?)",(sender,encode(card,MAX_CARD).decode(),verified["expires_ms"]))
        return {"peer":sender,"trusted_for_work":sender in self.pinned,"metadata_only":sender not in self.pinned}
    def cards(self,now_ms=None):
        now_ms=now_ms if now_ms is not None else int(time.time()*1000)
        return [decode(r[0].encode(),MAX_CARD) for r in self.db.db.execute("SELECT body FROM discovery WHERE expires_ms>?",(now_ms,)).fetchall()]
    def join_artifact(self,row,lineage_mapping=None,now_ms=None):
        # This schema matches 0.35 ModelCatalog::PersistLocked at the pinned HEAD.
        require(row.get("bytes_verified") is True and row.get("incomplete") is False,"MODEL_NOT_ACQUIRED")
        artifact=fixed_id(row["artifact_id"]);model=fixed_id(row["model_id"])
        mapping=(lineage_mapping or {}).get(artifact)
        if mapping:
            # Mapping must be installed locally from independently verified provenance.
            lineage=fixed_id(mapping["lineage_id"]);visibility=mapping.get("visibility","private")
            require(visibility in ("private","public"),"VISIBILITY")
        else:
            lineage=digest("BTX/ProvisionalModelTopic/1",{"model_id":model})
            visibility="private"
        r={"artifact_id":artifact,"model_id":model,"lineage_id":lineage,"lineage_assurance":"VERIFIED_MAPPING" if mapping else "PROVISIONAL_NOT_AUTHORITATIVE",
           "visibility":visibility,"role":"observer","channel":"general/stable","discovery":True,
           "idle_compute_authorized":False,"private_data_training":False,"automatic_activation":"FOLLOW_LOCAL_POLICY"}
        with self.db.tx() as c:c.execute("INSERT OR REPLACE INTO subscriptions VALUES(?,?,?,?)",(artifact,lineage,encode(r).decode(),now_ms or int(time.time()*1000)))
        return r
    def public_lineages(self):
        rows=self.db.db.execute("SELECT body FROM subscriptions").fetchall()
        return sorted({r["lineage_id"] for row in rows if (r:=decode(row[0].encode()))["visibility"]=="public"})


class CatalogWatcher:
    def __init__(self,catalog:Path,book:DiscoveryBook,mappings:Path|None=None):
        self.catalog=Path(catalog);self.book=book;self.mappings=mappings;self.stamp=None
        self.status={"state":"WAITING_FOR_CATALOG","joined":0}
    def poll(self):
        if not self.catalog.exists():return []
        require(not self.catalog.is_symlink(),"CATALOG_SYMLINK")
        stat=self.catalog.stat();require(stat.st_size<=32*1024*1024,"CATALOG_LIMIT")
        stamp=(stat.st_mtime_ns,stat.st_size)
        if stamp==self.stamp:return []
        # Native catalog JSON can contain values outside the control codec profile;
        # only the exact whitelisted acquisition fields are consumed below.
        try:root=json.loads(self.catalog.read_bytes())
        except ValueError as e:raise MeshError("CATALOG_JSON") from e
        require(isinstance(root,dict) and isinstance(root.get("models",[]),list),"CATALOG_SCHEMA")
        mappings={}
        if self.mappings and self.mappings.exists():mappings=decode(self.mappings.read_bytes())
        joined=[]
        for row in root.get("models",[]):
            if row.get("bytes_verified") is True and row.get("incomplete",False) is False:
                joined.append(self.book.join_artifact({**row,"incomplete":False},mappings))
        self.stamp=stamp;self.status={"state":"WATCHING","joined":len(joined)}
        return joined


def neighbors(peers:list[dict],near=4,remote=2):
    """Measured latency is locality. Administrative independence is pinned policy."""
    eligible=[p for p in peers if p.get("authorized",False) and p.get("available",False)]
    eligible.sort(key=lambda p:(p.get("rtt_us",2**63),-p.get("bandwidth_bps",0),p["id"]))
    chosen=eligible[:near];used={p["id"] for p in chosen};domains={p["domain"] for p in chosen}
    remaining=[p for p in eligible if p["id"] not in used]
    remaining.sort(key=lambda p:(p["domain"] in domains,p.get("rtt_us",2**63),p["id"]))
    return chosen+remaining[:remote]


class LanDiscovery(asyncio.DatagramProtocol):
    def __init__(self,identity,book,endpoint,stop):
        self.identity,self.book,self.endpoint,self.stop=identity,book,endpoint,stop
        self.transport=None;self.rate={};self.inflight=set();self.status="NOT_BOUND"
    def connection_made(self,transport):self.transport=transport;self.status="LISTENING"
    def datagram_received(self,data,addr):
        if len(data)>MAX_CARD or len(self.inflight)>=4:return
        now=time.monotonic();last=self.rate.get(addr[0],0)
        if now-last<0.5:return
        if len(self.rate)>1024:self.rate={k:v for k,v in self.rate.items() if now-v<10}
        self.rate[addr[0]]=now
        async def receive():
            try:
                card=decode(data,MAX_CARD)
                if card["envelope"]["body"]["sender"]!=self.identity.id:
                    await asyncio.to_thread(self.book.accept,card)
            except (MeshError,KeyError,ValueError):pass
        task=asyncio.create_task(receive());self.inflight.add(task);task.add_done_callback(self.inflight.discard)
    async def announce(self):
        while not self.stop.is_set():
            if self.transport:
                payload={"kind":"presence","peer":self.identity.id,"endpoint":self.endpoint,"lineages":self.book.public_lineages()[:16],"protocols":["BTX-SWARM/1"]}
                env=await asyncio.to_thread(self.identity.envelope,payload)
                raw=encode({"public_key":self.identity.public,"envelope":env},MAX_CARD)
                self.transport.sendto(raw,(MULTICAST,PORT))
            try:await asyncio.wait_for(self.stop.wait(),10)
            except asyncio.TimeoutError:pass
    async def start(self):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.bind(("",PORT));sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MULTICAST)+socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,1);sock.setblocking(False)
            await asyncio.get_running_loop().create_datagram_endpoint(lambda:self,sock=sock)
        except OSError:
            sock.close();self.status="LAN_MULTICAST_UNAVAILABLE";return
        await self.announce()
    async def close(self):
        if self.transport:self.transport.close()
        if self.inflight:await asyncio.gather(*self.inflight,return_exceptions=True)

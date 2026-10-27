"""Durable Raft for a pinned, static voter committee; workers need not be voters.

TLS authenticates peer IDs. Wire inputs are bounded by the HTTP layer. Dynamic
voter-set changes are deliberately rejected: joint consensus is not simulated
by silently editing the configuration file. This module never signs payments.
"""
import asyncio
import json
import random
import time
from collections.abc import Awaitable, Callable
from .codec import encode, decode, digest, integer, command_digest
from .errors import MeshError, require
from .storage import Database


class Raft:
    def __init__(self, db: Database, node_id: str, voters: list[str], send: Callable,
                 reducer, *, election=(0.8, 1.4), heartbeat=0.15):
        require(node_id in voters and len(set(voters)) == len(voters), "VOTER_CONFIG")
        require(1 <= len(voters) <= 31, "VOTER_LIMIT")
        self.db, self.id, self.voters, self.send, self.reducer = db, node_id, sorted(voters), send, reducer
        self.election, self.heartbeat = election, heartbeat
        self.mu = asyncio.Lock(); self.proposal_mu = asyncio.Lock()
        self.peer_mu = {p: asyncio.Lock() for p in voters if p != node_id}
        self.stop_event = asyncio.Event(); self.task = None
        self.role = "follower"; self.leader = None
        self.next_index = {}; self.match_index = {}
        # executescript commits implicitly; schema creation occurs outside tx.
        db.db.executescript("""
        CREATE TABLE IF NOT EXISTS raft_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS raft_log(idx INTEGER PRIMARY KEY,term INTEGER NOT NULL,command TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS raft_snapshot(singleton INTEGER PRIMARY KEY CHECK(singleton=1),body TEXT NOT NULL);
        """)
        cfg = digest("BTX/StaticCommittee/1", self.voters)
        with db.tx() as c:
            for k, v in {"term": "0", "vote": "", "commit": "0", "applied": "0", "snap_index": "0", "snap_term": "0", "committee": cfg}.items():
                c.execute("INSERT OR IGNORE INTO raft_meta VALUES(?,?)", (k,v))
            require(self.meta("committee", c)==cfg,"COMMITTEE_CHANGED", "use a reviewed migration, not edited voters")
        self.reset_deadline()
        with db.tx() as c: self.apply_committed(c)
    def meta(self, key, c=None):
        return (c or self.db.db).execute("SELECT value FROM raft_meta WHERE key=?",(key,)).fetchone()[0]
    def number(self,key,c=None): return int(self.meta(key,c))
    def put(self,c,key,value): c.execute("UPDATE raft_meta SET value=? WHERE key=?",(str(value),key))
    def reset_deadline(self): self.deadline=time.monotonic()+random.uniform(*self.election)
    def last(self,c=None):
        c=c or self.db.db
        row=c.execute("SELECT idx,term FROM raft_log ORDER BY idx DESC LIMIT 1").fetchone()
        return (row[0],row[1]) if row else (self.number("snap_index",c),self.number("snap_term",c))
    def term_at(self,index,c=None):
        c=c or self.db.db
        if index==0:return 0
        if index==self.number("snap_index",c):return self.number("snap_term",c)
        row=c.execute("SELECT term FROM raft_log WHERE idx=?",(index,)).fetchone()
        return row[0] if row else None
    def step_down(self,c,term,leader=None):
        if term>self.number("term",c): self.put(c,"term",term);self.put(c,"vote","")
        self.role="follower";self.leader=leader;self.reset_deadline()
    def apply_committed(self,c):
        applied,committed=self.number("applied",c),self.number("commit",c)
        for idx in range(applied+1,committed+1):
            row=c.execute("SELECT term,command FROM raft_log WHERE idx=?",(idx,)).fetchone()
            require(row is not None,"LOG_GAP")
            command=decode(row[1].encode())
            self.reducer.apply(c,command,idx,row[0])
            self.put(c,"applied",idx)
    async def handle(self, peer, method, p):
        require(peer in self.voters and peer != self.id,"VOTER_AUTH")
        if method=="vote":return await self.vote(peer,p)
        if method=="append":return await self.append(peer,p)
        if method=="snapshot":return await self.install_snapshot(peer,p)
        raise MeshError("RAFT_METHOD")
    async def vote(self,peer,p):
        async with self.mu:
            with self.db.tx() as c:
                t=integer(p["term"],0,2**63-1)
                if t>self.number("term",c):self.step_down(c,t)
                li,lt=self.last(c)
                eligible=(p["last_term"],p["last_index"]) >= (lt,li)
                granted=(t==self.number("term",c) and self.meta("vote",c) in ("",peer) and eligible)
                if granted:self.put(c,"vote",peer);self.reset_deadline()
                return {"term":self.number("term",c),"granted":granted}
    async def append(self,peer,p):
        require(isinstance(p["entries"],list) and len(p["entries"])<=64,"APPEND_LIMIT")
        async with self.mu:
            with self.db.tx() as c:
                t=integer(p["term"],0,2**63-1)
                if t<self.number("term",c):return {"term":self.number("term",c),"success":False,"next":self.last(c)[0]+1}
                self.step_down(c,t,peer)
                prev=integer(p["prev_index"],0,2**63-1)
                if self.term_at(prev,c)!=p["prev_term"]:
                    return {"term":t,"success":False,"next":max(1,min(prev,self.last(c)[0]+1))}
                for offset,entry in enumerate(p["entries"],prev+1):
                    require(entry["index"]==offset,"APPEND_GAP")
                    integer(entry["term"],1,t)
                    old=c.execute("SELECT term,command FROM raft_log WHERE idx=?",(offset,)).fetchone()
                    raw=encode(entry["command"]).decode()
                    if old and old[0]!=entry["term"]:
                        require(offset>self.number("commit",c),"COMMITTED_CONFLICT")
                        c.execute("DELETE FROM raft_log WHERE idx>=?",(offset,));old=None
                    if old:require(old[1]==raw,"TERM_EQUIVOCATION")
                    else:c.execute("INSERT INTO raft_log VALUES(?,?,?)",(offset,entry["term"],raw))
                # Only entries covered by this AppendEntries establish leader agreement.
                match=prev+len(p["entries"])
                new_commit=max(self.number("commit",c),min(p["leader_commit"],match))
                self.put(c,"commit",new_commit);self.apply_committed(c)
                return {"term":t,"success":True,"match":match}
    async def campaign(self):
        async with self.mu:
            if time.monotonic()<self.deadline or self.role=="leader":return
            with self.db.tx() as c:
                term=self.number("term",c)+1
                self.put(c,"term",term);self.put(c,"vote",self.id)
                li,lt=self.last(c)
            self.role="candidate";self.leader=None;self.reset_deadline()
        request={"term":term,"last_index":li,"last_term":lt}
        async def ask(peer):
            try:return await self.send(peer,"vote",request)
            except (Exception,asyncio.TimeoutError):return None
        replies=await asyncio.gather(*(ask(p) for p in self.peer_mu))
        async with self.mu:
            with self.db.tx() as c:
                largest=max([term]+[r["term"] for r in replies if r])
                if largest>self.number("term",c):self.step_down(c,largest);return
                if self.role!="candidate" or self.number("term",c)!=term:return
                count=1+sum(1 for r in replies if r and r["term"]==term and r["granted"])
                if count<=len(self.voters)//2:return
                self.role="leader";self.leader=self.id
                idx=self.last(c)[0]+1
                cmd={"kind":"__epoch__","id":f"epoch:{term}","actor":self.id,"time_ms":int(time.time()*1000),"body":{}}
                c.execute("INSERT INTO raft_log VALUES(?,?,?)",(idx,term,encode(cmd).decode()))
                self.next_index={p:idx for p in self.peer_mu};self.match_index={p:0 for p in self.peer_mu}
                self.advance_commit(c)
        await self.replicate_all()
    def advance_commit(self,c):
        matches=sorted([self.last(c)[0]]+[self.match_index.get(p,0) for p in self.peer_mu],reverse=True)
        idx=matches[len(self.voters)//2]
        if idx>self.number("commit",c) and self.term_at(idx,c)==self.number("term",c):
            self.put(c,"commit",idx);self.apply_committed(c)
    async def replicate_peer(self,peer):
        async with self.peer_mu[peer]:
            for _ in range(16):
                async with self.mu:
                    if self.role!="leader":return
                    term=self.number("term");n=self.next_index[peer]
                    snap=n<=self.number("snap_index")
                    if snap:
                        row=self.db.db.execute("SELECT body FROM raft_snapshot WHERE singleton=1").fetchone()
                        require(row is not None,"SNAPSHOT_MISSING")
                        payload={"term":term,"snapshot":decode(row[0].encode(),64*1024*1024)}
                    else:
                        rows=self.db.db.execute("SELECT idx,term,command FROM raft_log WHERE idx>=? ORDER BY idx LIMIT 16",(n,)).fetchall()
                        payload={"term":term,"prev_index":n-1,"prev_term":self.term_at(n-1),"leader_commit":self.number("commit"),
                                 "entries":[{"index":r[0],"term":r[1],"command":decode(r[2].encode())} for r in rows]}
                try:reply=await self.send(peer,"snapshot" if snap else "append",payload)
                except (Exception,asyncio.TimeoutError):return
                async with self.mu:
                    with self.db.tx() as c:
                        if reply["term"]>self.number("term",c):self.step_down(c,reply["term"]);return
                        if self.role!="leader" or self.number("term",c)!=term:return
                        if reply["success"]:
                            matched=reply["match"]
                            self.match_index[peer]=max(self.match_index[peer],matched)
                            self.next_index[peer]=self.match_index[peer]+1
                            self.advance_commit(c)
                            if self.next_index[peer]>self.last(c)[0]:return
                        else:self.next_index[peer]=max(1,min(n-1,reply.get("next",n-1)))
    async def replicate_all(self):
        if self.role=="leader":await asyncio.gather(*(self.replicate_peer(p) for p in self.peer_mu))
    async def propose(self,cmd,timeout=8.0):
        encode(cmd,256*1024)
        async with self.proposal_mu:
            async with self.mu:
                require(self.role=="leader","NOT_LEADER",self.leader or "election")
                with self.db.tx() as c:
                    existing=self.reducer.result(c,cmd["id"])
                    if existing:
                        require(existing[0]==command_digest(cmd),"IDEMPOTENCY_CONFLICT")
                        return existing[1]
                    term=self.number("term",c);idx=self.last(c)[0]+1
                    c.execute("INSERT INTO raft_log VALUES(?,?,?)",(idx,term,encode(cmd).decode()))
                    self.advance_commit(c)
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                await self.replicate_all()
                async with self.mu:
                    result=self.reducer.result(self.db.db,cmd["id"])
                    if result:return result[1]
                    require(self.role=="leader" and self.number("term")==term,"LEADERSHIP_CHANGED", "query command id before retrying")
                await asyncio.sleep(0.025)
            raise MeshError("COMMIT_UNKNOWN","query command id; timeout does not cancel a committed operation")
    async def snapshot(self):
        async with self.mu:
            with self.db.tx() as c:
                idx=self.number("applied",c)
                if idx==0:return None
                snap={"index":idx,"term":self.term_at(idx,c),"committee":self.meta("committee",c),"state":self.reducer.export(c)}
                raw=encode(snap,64*1024*1024).decode()
                c.execute("INSERT OR REPLACE INTO raft_snapshot VALUES(1,?)",(raw,))
                self.put(c,"snap_index",idx);self.put(c,"snap_term",snap["term"])
                c.execute("DELETE FROM raft_log WHERE idx<=?",(idx,))
                return {"index":idx,"digest":digest("BTX/SnapshotIndex/1",{"index":idx,"term":snap["term"]})}
    async def install_snapshot(self,peer,p):
        snap=p["snapshot"]
        require(len(encode(snap,64*1024*1024))<=64*1024*1024,"SNAPSHOT_LIMIT")
        async with self.mu:
            with self.db.tx() as c:
                if p["term"]<self.number("term",c):return {"term":self.number("term",c),"success":False}
                self.step_down(c,p["term"],peer)
                require(snap["committee"]==self.meta("committee",c),"COMMITTEE_MISMATCH")
                if snap["index"]<=self.number("commit",c):
                    return {"term":self.number("term",c),"success":True,"match":self.number("commit",c)}
                if self.term_at(snap["index"],c)!=snap["term"]:c.execute("DELETE FROM raft_log")
                else:c.execute("DELETE FROM raft_log WHERE idx<=?",(snap["index"],))
                self.reducer.restore(c,snap["state"])
                for key,val in {"snap_index":snap["index"],"snap_term":snap["term"],"commit":snap["index"],"applied":snap["index"]}.items():self.put(c,key,val)
                c.execute("INSERT OR REPLACE INTO raft_snapshot VALUES(1,?)",(encode(snap,64*1024*1024).decode(),))
                return {"term":self.number("term",c),"success":True,"match":snap["index"]}
    async def run(self):
        while not self.stop_event.is_set():
            try:
                if self.role=="leader":await self.replicate_all()
                elif time.monotonic()>=self.deadline:await self.campaign()
            except asyncio.CancelledError:raise
            # Unknown reducer or disk errors are fatal rather than silently ignored.
            try:await asyncio.wait_for(self.stop_event.wait(),timeout=self.heartbeat)
            except asyncio.TimeoutError:pass
    def start(self):self.task=asyncio.create_task(self.run());return self.task
    async def stop(self):
        self.stop_event.set()
        if self.task:
            await self.task

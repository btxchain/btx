"""Deterministic replicated model/swarm state. Every mutation is a Raft command.

No model tensors, dataset contents, wallet keys or chain-state changes occur here.
All commands are committed as successes or typed rejections, with idempotency.
"""
import json
from .codec import encode, decode, digest, fixed_id, fields, integer, command_digest
from .errors import MeshError, require
from .evaluation import qualify_report

EXECUTORS = {"torch.train","torch.rollout","torch.evaluate","inference","dataset.verify"}
ROLES = {"observer","worker","trainer","evaluator","admin","treasury"}
TABLES = {
    "mesh_objects": ("kind","key","realm","parent","body"),
    "mesh_commands": ("id","hash","result"),
    "mesh_authorizations": ("id","body"),
    "mesh_events": ("seq","term","command_id"),
    "mesh_jobs": ("id","realm","state","assigned","priority","deadline"),
}


def default_policy(suite_id: str, holdout: str):
    return {"min_evaluators":3,"min_domains":2,"max_trials":100,"alpha_ppm":50000,
            "min_examples":10000,"min_gain_ppm":20000,"suite_id":suite_id,"holdout_commitment":holdout,
            "max_regression_ppm":{"safety":0,"general":10000},"canary_min":5,"canary_failures":0,
            "lease_ms":60000,"max_jobs":100000,"max_vram_bytes":2**40,"max_attempts":3}


from .cohorts import CohortOps

class State(CohortOps):
    def __init__(self, db, bootstrap_roots: list[str]):
        self.db=db;self.bootstrap_roots=set(bootstrap_roots)
        db.db.executescript("""
        CREATE TABLE IF NOT EXISTS mesh_objects(kind TEXT NOT NULL,key TEXT NOT NULL,realm TEXT NOT NULL,parent TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(kind,key));
        CREATE INDEX IF NOT EXISTS mesh_objects_scope ON mesh_objects(kind,realm,parent);
        CREATE TABLE IF NOT EXISTS mesh_commands(id TEXT PRIMARY KEY,hash TEXT NOT NULL,result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS mesh_authorizations(id TEXT PRIMARY KEY,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS mesh_events(seq INTEGER PRIMARY KEY,term INTEGER NOT NULL,command_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS mesh_jobs(id TEXT PRIMARY KEY,realm TEXT NOT NULL,state TEXT NOT NULL,assigned TEXT NOT NULL,priority INTEGER NOT NULL,deadline INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS mesh_ready ON mesh_jobs(realm,state,priority,deadline);
        CREATE INDEX IF NOT EXISTS mesh_assigned ON mesh_jobs(assigned,state);
        """)
    def get(self,c,kind,key,required=True):
        row=c.execute("SELECT body FROM mesh_objects WHERE kind=? AND key=?",(kind,key)).fetchone()
        if row is None:
            require(not required,"NOT_FOUND",kind)
            return None
        return decode(row[0].encode())
    def put(self,c,kind,key,body):
        c.execute("INSERT OR REPLACE INTO mesh_objects VALUES(?,?,?,?,?)",
                  (kind,key,body.get("realm",""),body.get("parent",body.get("candidate","")),encode(body).decode()))
        if kind=="job":
            c.execute("INSERT OR REPLACE INTO mesh_jobs VALUES(?,?,?,?,?,?)",
                      (key,body["realm"],body["state"],body.get("assigned",""),body["priority"],body["deadline_ms"]))
    def scan(self,c,kind,realm=None,parent=None,limit=100000):
        require(type(limit) is int and 0<limit<=100000,"QUERY_LIMIT")
        clauses=["kind=?"];args=[kind]
        if realm is not None:clauses.append("realm=?");args.append(realm)
        if parent is not None:clauses.append("parent=?");args.append(parent)
        rows=c.execute("SELECT body FROM mesh_objects WHERE "+" AND ".join(clauses)+" ORDER BY key LIMIT ?",(*args,limit+1)).fetchall()
        require(len(rows)<=limit,"SCAN_RANGE_INCOMPLETE","internal invariant scan cannot silently truncate")
        return [decode(r[0].encode()) for r in rows]
    def page(self,c,kind,realm=None,parent=None,limit=256,cursor=None):
        import base64
        integer(limit,1,1000)
        scope=digest("BTX/QueryScope/1",{"kind":kind,"realm":realm,"parent":parent})
        clauses=["kind=?"];args=[kind]
        if realm is not None:clauses.append("realm=?");args.append(realm)
        if parent is not None:clauses.append("parent=?");args.append(parent)
        if cursor is not None:
            require(isinstance(cursor,str) and len(cursor)<=4096,"QUERY_CURSOR")
            try: value=decode(base64.b64decode(cursor,altchars=b"-_",validate=True),4096)
            except (ValueError,TypeError) as e:raise MeshError("QUERY_CURSOR") from e
            fields(value,{"scope","after"})
            require(value["scope"]==scope and isinstance(value["after"],str),"QUERY_CURSOR_SCOPE")
            clauses.append("key>?");args.append(value["after"])
        rows=c.execute("SELECT key,body FROM mesh_objects WHERE "+" AND ".join(clauses)+" ORDER BY key LIMIT ?",(*args,limit+1)).fetchall()
        more=len(rows)>limit;rows=rows[:limit]
        next_cursor=base64.urlsafe_b64encode(encode({"scope":scope,"after":rows[-1]["key"]})).decode() if more else None
        return [decode(r["body"].encode()) for r in rows],next_cursor
    def result(self,c,id):
        row=c.execute("SELECT hash,result FROM mesh_commands WHERE id=?",(id,)).fetchone()
        return (row[0],decode(row[1].encode())) if row else None
    def member(self,c,realm,actor,roles=None):
        r=self.get(c,"realm",realm)
        if actor==r["owner"]:return {"roles":sorted(ROLES),"domain":r["owner_domain"],"max_slots":1024,"max_vram_bytes":r["policy"]["max_vram_bytes"],"generation":"owner","revoked":False}
        m=self.get(c,"member",f"{realm}:{actor}",False)
        require(m is not None and not m["revoked"],"MEMBERSHIP")
        if roles:require(bool(set(m["roles"])&set(roles)),"ROLE")
        return m
    def administrative(self,c,realm,actor):return self.member(c,realm,actor,{"admin"})
    def apply(self,c,command,index,term):
        # A rejected command must not terminate replication or partially mutate state.
        ch=command_digest(command)
        existing=self.result(c,command["id"])
        if existing:
            result=existing[1] if ch==existing[0] else {"error":"IDEMPOTENCY_CONFLICT","detail":""}
            c.execute("INSERT INTO mesh_events VALUES(?,?,?)",(index,term,command["id"]))
            return result
        c.execute("SAVEPOINT command")
        try:
            fields(command,{"kind","id","actor","time_ms","body"},{"authorization"})
            require(isinstance(command["id"],str) and 0<len(command["id"])<=128,"COMMAND_ID")
            integer(command["time_ms"],0,2**63-1)
            old=self.get(c,"system","epoch",False)
            if old is None or old["term"]<term:
                self.put(c,"system","epoch",{"term":term})
                # Old results cannot enter a new generation. Physical allocations remain
                # charged until their worker sends quiescence or proves a process restart.
                rows=c.execute("SELECT id FROM mesh_jobs WHERE state='RUNNING'").fetchall()
                for row in rows:
                    job=self.get(c,"job",row[0]);job["state"]="QUEUED";job["assigned"]="";self.put(c,"job",job["id"],job)
            kind=command["kind"]
            if kind.startswith("__"):
                require(kind in {"__epoch__","__barrier__"},"METHOD")
                result={"term":term,"index":index}
            else:
                fn=getattr(self,"op_"+kind.replace(".","_"),None)
                require(fn is not None,"METHOD",kind)
                result=fn(c,command["actor"],command["body"],command["time_ms"],term)
                if kind=="evaluation.publish" and "authorization" in command:
                    result["authorization"]=command["authorization"]
                    self.put(c,"evaluation",result["id"],result)
            encode(result)
            c.execute("RELEASE command")
        except (MeshError,KeyError,TypeError,ValueError) as e:
            c.execute("ROLLBACK TO command");c.execute("RELEASE command")
            result=e.json() if isinstance(e,MeshError) else {"error":"SCHEMA","detail":str(e)[:160]}
        c.execute("INSERT INTO mesh_commands VALUES(?,?,?)",(command["id"],ch,encode(result).decode()))
        if "authorization" in command:
            c.execute("INSERT INTO mesh_authorizations VALUES(?,?)",(command["id"],encode(command["authorization"]).decode()))
        c.execute("INSERT INTO mesh_events VALUES(?,?,?)",(index,term,command["id"]))
        return result
    def export(self,c):
        return {table:[dict(row) for row in c.execute(f"SELECT * FROM {table}").fetchall()] for table in TABLES}
    def restore(self,c,body):
        require(set(body)==set(TABLES),"SNAPSHOT_SCHEMA")
        for table,columns in TABLES.items():
            c.execute(f"DELETE FROM {table}")
            for row in body[table]:
                require(set(row)==set(columns),"SNAPSHOT_COLUMNS")
                c.execute(f"INSERT INTO {table} VALUES({','.join('?' for _ in columns)})",tuple(row[x] for x in columns))
    def op_realm_create(self,c,actor,b,now,term):
        fields(b,{"name","nonce","owner_domain","policy"})
        require(actor in self.bootstrap_roots,"BOOTSTRAP_AUTHORITY")
        p=b["policy"]
        fields(p,set(default_policy("","")))
        integer(p["min_evaluators"],1,31);integer(p["min_domains"],1,p["min_evaluators"])
        integer(p["max_trials"],1,1000000);integer(p["lease_ms"],1000,300000)
        integer(p["max_jobs"],1,100000);integer(p["max_attempts"],1,16)
        integer(p["alpha_ppm"],1,500000);integer(p["min_examples"],1,100000000)
        integer(p["min_gain_ppm"],0,1000000);integer(p["max_vram_bytes"],0,2**50)
        integer(p["canary_min"],1,100000);integer(p["canary_failures"],0,p["canary_min"])
        fixed_id(p["suite_id"]);fixed_id(p["holdout_commitment"])
        require(type(p["max_regression_ppm"]) is dict and len(p["max_regression_ppm"])<=32,"REGRESSION_POLICY")
        for value in p["max_regression_ppm"].values():integer(value,0,1000000)
        id=digest("BTX/SwarmRealm/1",{"owner":actor,**b})
        r={"id":id,"realm":id,"owner":actor,"owner_domain":b["owner_domain"],"name":b["name"],"policy":p,"policy_epoch":1,"trials":0}
        require(self.get(c,"realm",id,False) is None,"EXISTS")
        self.put(c,"realm",id,r);return r
    def op_member_grant(self,c,actor,b,now,term):
        fields(b,{"realm","peer","roles","domain","max_slots","max_vram_bytes"})
        self.administrative(c,b["realm"],actor);fixed_id(b["peer"])
        require(type(b["roles"]) is list and set(b["roles"])<=ROLES,"ROLES")
        require(bool(b["domain"]) and len(b["domain"])<=128,"TRUST_DOMAIN")
        integer(b["max_slots"],0,1024);integer(b["max_vram_bytes"],0,2**50)
        r={**b,"revoked":False};self.put(c,"member",f'{b["realm"]}:{b["peer"]}',r);return r
    def op_member_revoke(self,c,actor,b,now,term):
        fields(b,{"realm","peer"});self.administrative(c,b["realm"],actor)
        m=self.get(c,"member",f'{b["realm"]}:{b["peer"]}')
        m["revoked"]=True;self.put(c,"member",f'{b["realm"]}:{b["peer"]}',m)
        for job in self.scan(c,"job",b["realm"]):
            if job.get("assigned")==b["peer"] and job["state"]=="RUNNING":
                job["state"]="CANCELLING";self.put(c,"job",job["id"],job)
        return {"revoked":True,"physical_quiescence":"NOT_ASSUMED"}
    def op_family_register(self,c,actor,b,now,term):
        fields(b,{"realm","genesis_checkpoint","origin","license_id","nonce","name"})
        self.member(c,b["realm"],actor,{"trainer","admin"});fixed_id(b["genesis_checkpoint"]);fixed_id(b["license_id"])
        id=digest("BTX/ModelLineage/1",{"author":actor,**b})
        require(self.get(c,"family",id,False) is None,"EXISTS")
        r={**b,"id":id,"author":actor,"heads":[],"membership_default":"OBSERVER"}
        self.put(c,"family",id,r)
        self.put(c,"subscription",f'{id}:{actor}',{"realm":b["realm"],"parent":id,"peer":actor,"channel":"general/stable","automatic_discovery":True,"idle_compute":False,"private_data_training":False})
        return r
    def op_family_subscribe(self,c,actor,b,now,term):
        fields(b,{"family","channel","idle_compute","private_data_training"})
        f=self.get(c,"family",b["family"]);self.member(c,f["realm"],actor)
        require(type(b["idle_compute"]) is bool and b["private_data_training"] is False,"CONSENT", "private datasets need per-dataset grants")
        r={**b,"realm":f["realm"],"parent":b["family"],"peer":actor,"automatic_discovery":True}
        self.put(c,"subscription",f'{b["family"]}:{actor}',r);return r
    def op_presence_publish(self,c,actor,b,now,term):
        fields(b,{"realm","generation","slots","vram_bytes","runtimes","expires_ms","checkpoint_ids"})
        m=self.member(c,b["realm"],actor)
        integer(b["slots"],0,m["max_slots"]);integer(b["vram_bytes"],0,m["max_vram_bytes"])
        require(now<b["expires_ms"]<=now+120000,"PRESENCE_TTL")
        require(isinstance(b["generation"],str) and 16<=len(b["generation"])<=128,"GENERATION")
        old=self.get(c,"presence",f'{b["realm"]}:{actor}',False)
        if old and old["generation"]!=b["generation"]:
            # New process generation is a signed worker assertion; it is not remote
            # hardware attestation. A worker remains accountable for old effects.
            for a in self.scan(c,"allocation",b["realm"],actor):
                a["state"]="RETIRED_BY_WORKER_RESTART";self.put(c,"allocation",a["id"],a)
        r={**b,"peer":actor,"parent":actor};self.put(c,"presence",f'{b["realm"]}:{actor}',r);return r
    def op_work_submit(self,c,actor,b,now,term):
        fields(b,{"realm","tasks"});self.member(c,b["realm"],actor,{"admin","trainer"})
        realm=self.get(c,"realm",b["realm"])
        require(isinstance(b["tasks"],list) and 1<=len(b["tasks"])<=128,"BATCH_LIMIT")
        count=c.execute("SELECT COUNT(*) FROM mesh_jobs WHERE realm=?",(b["realm"],)).fetchone()[0]
        require(count+len(b["tasks"])<=realm["policy"]["max_jobs"],"JOB_QUOTA")
        pending={}
        for task in b["tasks"]:
            fields(task,{"id","executor","checkpoint","recipe","deps","priority","deadline_ms","vram_bytes","payload"})
            require(task["executor"] in EXECUTORS,"EXECUTOR")
            require(type(task["id"]) is str and 0<len(task["id"])<=128,"TASK_ID")
            require(task["id"] not in pending and self.get(c,"job",task["id"],False) is None,"EXISTS")
            integer(task["priority"],0,100);integer(task["vram_bytes"],0,realm["policy"]["max_vram_bytes"])
            require(now<task["deadline_ms"]<=now+30*86400000,"TASK_DEADLINE")
            require(len(task["deps"])<=128 and len(set(task["deps"]))==len(task["deps"]),"DEPENDENCIES")
            fixed_id(task["checkpoint"]);fixed_id(task["recipe"])
            require(isinstance(task["payload"],dict),"PAYLOAD_SCHEMA")
            payload=task["payload"]
            require(not (set(payload)&{"credential","credentials","secret","api_key","password","private_key"}),"SECRET_IN_CONTROL_PLANE")
            if "tokens" in payload:
                require(payload.get("data_class")=="PUBLIC_SYNTHETIC","PRIVATE_PROMPT_CONTROL_PLANE")
                require(isinstance(payload["tokens"],list) and 1<=len(payload["tokens"])<=32768,"TOKEN_COUNT")
                for token in payload["tokens"]:integer(token,0,65535)
            pending[task["id"]]={**task,"realm":b["realm"],"submitter":actor,"state":"QUEUED","attempts":0,"assigned":""}
        done=set()
        def visit(id,stack):
            if id in done:return
            require(id not in stack,"DAG_CYCLE")
            if id not in pending:
                j=self.get(c,"job",id);require(j["realm"]==b["realm"],"DEPENDENCY_REALM");return
            for d in pending[id]["deps"]:visit(d,stack|{id})
            done.add(id)
        for id in pending:visit(id,set())
        for id,job in pending.items():self.put(c,"job",id,job)
        return {"submitted":sorted(pending)}
    def op_work_claim(self,c,actor,b,now,term):
        fields(b,{"realm","job","generation","nonce"})
        m=self.member(c,b["realm"],actor,{"worker","trainer"})
        r=self.get(c,"realm",b["realm"]);j=self.get(c,"job",b["job"])
        require(j["realm"]==b["realm"],"TASK_REALM")
        require(j["state"]=="QUEUED" and j["deadline_ms"]>now,"TASK_UNAVAILABLE")
        require(j["attempts"]<r["policy"]["max_attempts"],"ATTEMPT_LIMIT")
        require(all(self.get(c,"job",dep)["state"]=="COMPLETE" for dep in j["deps"]),"DEPENDENCY_WAIT")
        presence=self.get(c,"presence",f'{b["realm"]}:{actor}')
        require(presence["expires_ms"]>now and presence["generation"]==b["generation"],"WORKER_STALE")
        require(j["executor"] in presence["runtimes"],"RUNTIME_UNAVAILABLE")
        allocations=[a for a in self.scan(c,"allocation",b["realm"],actor) if a["state"]=="ACTIVE"]
        require(len(allocations)<min(m["max_slots"],presence["slots"]),"SLOTS_EXHAUSTED")
        require(sum(a["vram_bytes"] for a in allocations)+j["vram_bytes"]<=min(m["max_vram_bytes"],presence["vram_bytes"]),"VRAM_EXHAUSTED")
        lease=digest("BTX/WorkLease/1",{"job":j["id"],"worker":actor,"term":term,"attempt":j["attempts"]+1,"nonce":b["nonce"]})
        j.update(state="RUNNING",assigned=actor,lease=lease,term=term,generation=b["generation"],expires_ms=min(j["deadline_ms"],now+r["policy"]["lease_ms"]),attempts=j["attempts"]+1)
        self.put(c,"job",j["id"],j)
        self.put(c,"allocation",lease,{"id":lease,"realm":j["realm"],"parent":actor,"worker":actor,"job":j["id"],"generation":b["generation"],"vram_bytes":j["vram_bytes"],"state":"ACTIVE"})
        return j
    def check_lease(self,c,actor,b,now,term,allow_expired=False):
        j=self.get(c,"job",b["job"])
        self.member(c,j["realm"],actor,{"worker","trainer"})
        require(j["state"]=="RUNNING" and j["assigned"]==actor,"LEASE_OWNER")
        require(j["lease"]==b["lease"] and j["term"]==term,"STALE_LEASE")
        if not allow_expired:require(j["expires_ms"]>now,"LEASE_EXPIRED")
        return j
    def op_work_renew(self,c,actor,b,now,term):
        fields(b,{"job","lease"});j=self.check_lease(c,actor,b,now,term)
        r=self.get(c,"realm",j["realm"])
        j["expires_ms"]=min(j["deadline_ms"],now+r["policy"]["lease_ms"]);self.put(c,"job",j["id"],j);return j
    def op_work_finish(self,c,actor,b,now,term):
        fields(b,{"job","lease","result_id","evidence"})
        fixed_id(b["result_id"])
        j=self.check_lease(c,actor,b,now,term)
        j.update(state="COMPLETE",result_id=b["result_id"],evidence=b["evidence"])
        self.put(c,"job",j["id"],j)
        a=self.get(c,"allocation",j["lease"]);a["state"]="QUIESCENT";self.put(c,"allocation",a["id"],a)
        return {"job":j["id"],"result_id":b["result_id"],"state":"COMPLETE","payment_status":"NOT_A_PAYMENT"}
    def op_work_cancel(self,c,actor,b,now,term):
        fields(b,{"job"});j=self.get(c,"job",b["job"])
        if actor!=j["submitter"]:self.administrative(c,j["realm"],actor)
        if j["state"]=="RUNNING":j["state"]="CANCELLING"
        elif j["state"]=="QUEUED":j["state"]="CANCELLED"
        else:require(j["state"] in {"CANCELLED","CANCELLING"},"TERMINAL_JOB")
        self.put(c,"job",j["id"],j);return {"state":j["state"],"physical_quiescent":j["state"]=="CANCELLED"}
    def op_work_quiesce(self,c,actor,b,now,term):
        fields(b,{"lease","generation"})
        a=self.get(c,"allocation",b["lease"])
        require(a["worker"]==actor and a["generation"]==b["generation"],"ALLOCATION_OWNER")
        # Revocation must not prevent the worker from acknowledging cancellation.
        a["state"]="QUIESCENT";self.put(c,"allocation",a["id"],a)
        j=self.get(c,"job",a["job"])
        if j.get("lease")==a["id"] and j["state"] in {"RUNNING","CANCELLING"}:
            j["state"]="CANCELLED" if j["state"]=="CANCELLING" else "QUEUED"
            j["assigned"]="";self.put(c,"job",j["id"],j)
        return {"quiescent":True}
    def op_work_expire(self,c,actor,b,now,term):
        fields(b,{"realm"});self.administrative(c,b["realm"],actor)
        expired=[]
        for j in self.scan(c,"job",b["realm"]):
            if j["state"]=="RUNNING" and j["expires_ms"]<=now:
                j["state"]="QUEUED" if j["deadline_ms"]>now else "FAILED"
                j["assigned"]="";self.put(c,"job",j["id"],j);expired.append(j["id"])
        return {"expired":expired,"allocations_released":False}
    def op_kv_announce(self,c,actor,b,now,term):
        fields(b,{"realm","fingerprint","prefix_key","artifact","bytes","expires_ms","producer_build","tokens","holder"})
        self.member(c,b["realm"],actor,{"worker","trainer"})
        for x in ("fingerprint","prefix_key","artifact","producer_build"):fixed_id(b[x])
        require(now<b["expires_ms"]<=now+3600000,"CACHE_TTL")
        integer(b["bytes"],1,2**40);integer(b["tokens"],1,1048576);fixed_id(b["holder"])
        id=digest("BTX/KVLocator/1",{"peer":actor,**b})
        r={**b,"id":id,"parent":b["prefix_key"],"peer":actor,"assurance":"PRODUCER_ASSERTED_NOT_COMPUTE_PROOF"}
        self.put(c,"kv",id,r);return r
    def op_candidate_submit(self,c,actor,b,now,term):
        fields(b,{"family","checkpoint","parents","recipe","kind","niche","license_id","data_grant_ids"})
        f=self.get(c,"family",b["family"]);self.member(c,f["realm"],actor,{"trainer","admin"})
        require(b["kind"] in {"base","adapter","distillation","merge","architecture"},"CANDIDATE_KIND")
        require(0<=len(b["parents"])<=8 and len(set(b["parents"]))==len(b["parents"]),"PARENTS")
        for parent in b["parents"]:
            p=self.get(c,"candidate",parent);require(p["family"]==b["family"],"PARENT_FAMILY")
        for x in ("checkpoint","recipe","license_id"):fixed_id(b[x])
        require(b["license_id"]==f["license_id"],"LICENSE_REVIEW_REQUIRED")
        id=digest("BTX/CandidateCheckpoint/1",{"author":actor,**b})
        require(self.get(c,"candidate",id,False) is None,"EXISTS")
        r=self.get(c,"realm",f["realm"])
        require(r["trials"]<r["policy"]["max_trials"],"TRIAL_BUDGET_EXHAUSTED")
        r["trials"]+=1;self.put(c,"realm",r["id"],r)
        id=digest("BTX/CandidateCheckpoint/1",{"author":actor,**b})
        candidate={**b,"id":id,"realm":f["realm"],"author":actor,"trial":r["trials"],"policy_epoch":r["policy_epoch"],"state":"EVALUATING"}
        self.put(c,"candidate",id,candidate)
        f["heads"]=sorted((set(f["heads"])-set(b["parents"]))|{id});self.put(c,"family",f["id"],f)
        return candidate
    def op_evaluation_publish(self,c,actor,b,now,term):
        fields(b,{"candidate","suite_id","holdout_commitment","counts","regressions_ppm","reproducible","environment_id","sample_commitment"})
        candidate=self.get(c,"candidate",b["candidate"])
        m=self.member(c,candidate["realm"],actor,{"evaluator"})
        require(actor!=candidate["author"],"INDEPENDENT_EVALUATOR")
        fixed_id(b["environment_id"]);fixed_id(b["sample_commitment"])
        # Negative evaluations remain first-class records and do not disappear.
        p=self.get(c,"realm",candidate["realm"])["policy"]
        try:bound=qualify_report(b,p);qualified=True;reason=""
        except MeshError as e:bound={};qualified=False;reason=e.code
        id=digest("BTX/EvaluationReport/1",{"evaluator":actor,**b})
        r={**b,"id":id,"realm":candidate["realm"],"evaluator":actor,"domain":m["domain"],"qualified":qualified,"reason":reason,"bound":bound}
        self.put(c,"evaluation",id,r);return r
    def op_candidate_graduate(self,c,actor,b,now,term):
        fields(b,{"candidate","reports","channel"})
        cand=self.get(c,"candidate",b["candidate"]);self.administrative(c,cand["realm"],actor)
        realm=self.get(c,"realm",cand["realm"]);p=realm["policy"]
        require(cand["policy_epoch"]==realm["policy_epoch"],"STALE_POLICY")
        require(1<=len(b["reports"])<=31 and len(set(b["reports"]))==len(b["reports"]),"EVALUATION_SET")
        reports=[self.get(c,"evaluation",id) for id in b["reports"]]
        roots=set();domains=set();sample=None
        for report in reports:
            require(report["candidate"]==cand["id"] and report["qualified"],"EVALUATION_NOT_QUALIFIED")
            m=self.member(c,cand["realm"],report["evaluator"],{"evaluator"})
            require(report["evaluator"] not in roots,"DUPLICATE_EVALUATOR")
            roots.add(report["evaluator"]);domains.add(m["domain"])
            if sample is None:sample=report["sample_commitment"]
            require(report["sample_commitment"]==sample,"EVALUATION_SAMPLE_MISMATCH")
        require(len(roots)>=p["min_evaluators"] and len(domains)>=p["min_domains"],"QUORUM")
        require(b["channel"]==cand["niche"]+"/stable","CHANNEL_OBJECTIVE")
        cert={"candidate":cand["id"],"realm":cand["realm"],"family":cand["family"],"channel":b["channel"],"reports":sorted(b["reports"]),"policy_epoch":realm["policy_epoch"],"created_ms":now}
        id=digest("BTX/PromotionCertificate/1",cert);cert["id"]=id
        self.put(c,"certificate",id,cert);cand["state"]="GRADUATED";self.put(c,"candidate",cand["id"],cand)
        return {"certificate":id,"checkpoint":cand["checkpoint"],"adoption":"NOT_YET_ACTIVE","public_admission":"SEPARATE_LAB_GATE"}
    def op_channel_stage(self,c,actor,b,now,term):
        fields(b,{"certificate","expected_sequence"})
        cert=self.get(c,"certificate",b["certificate"]);self.administrative(c,cert["realm"],actor)
        key=cert["family"]+":"+cert["channel"]
        old=self.get(c,"channel",key,False)
        require(b["expected_sequence"]==(old["sequence"] if old else 0),"CHANNEL_STALE")
        require(not old or old["state"]!="CANARY","CANARY_IN_PROGRESS")
        candidate=self.get(c,"candidate",cert["candidate"])
        r={"realm":cert["realm"],"family":cert["family"],"name":cert["channel"],"candidate":cert["candidate"],"certificate":cert["id"],"checkpoint":candidate["checkpoint"],"sequence":b["expected_sequence"]+1,"state":"CANARY","previous_checkpoint":old["checkpoint"] if old else None,"previous_candidate":old["candidate"] if old else None}
        self.put(c,"channel",key,r);return r
    def op_canary_observe(self,c,actor,b,now,term):
        fields(b,{"family","channel","sequence","success","receipt_id"})
        channel=self.get(c,"channel",b["family"]+":"+b["channel"])
        self.member(c,channel["realm"],actor,{"worker","evaluator","trainer"})
        require(channel["state"]=="CANARY" and channel["sequence"]==b["sequence"],"CANARY_STALE")
        require(type(b["success"]) is bool,"CANARY_RESULT");fixed_id(b["receipt_id"])
        key=digest("BTX/CanaryObservation/1",{"peer":actor,**b})
        self.put(c,"canary",key,{**b,"realm":channel["realm"],"parent":channel["certificate"],"peer":actor,"id":key})
        return {"observation":key}
    def op_channel_activate(self,c,actor,b,now,term):
        fields(b,{"family","channel","expected_sequence"})
        key=b["family"]+":"+b["channel"];ch=self.get(c,"channel",key);self.administrative(c,ch["realm"],actor)
        require(ch["state"]=="CANARY" and ch["sequence"]==b["expected_sequence"],"CHANNEL_STALE")
        p=self.get(c,"realm",ch["realm"])["policy"]
        observations=self.scan(c,"canary",ch["realm"],ch["certificate"])
        unique={(x["peer"],x["receipt_id"]):x for x in observations if x["sequence"]==ch["sequence"]}
        require(len(unique)>=p["canary_min"] and sum(not x["success"] for x in unique.values())<=p["canary_failures"],"CANARY_GATE")
        # Recheck revocation after staging; no grandfathered evaluator authority.
        cert=self.get(c,"certificate",ch["certificate"])
        for id in cert["reports"]:
            report=self.get(c,"evaluation",id);self.member(c,ch["realm"],report["evaluator"],{"evaluator"})
        ch["state"]="ACTIVE";self.put(c,"channel",key,ch);return ch
    def op_channel_rollback(self,c,actor,b,now,term):
        fields(b,{"family","channel","expected_sequence","reason"})
        key=b["family"]+":"+b["channel"];ch=self.get(c,"channel",key);self.administrative(c,ch["realm"],actor)
        require(ch["sequence"]==b["expected_sequence"] and ch["previous_checkpoint"] is not None,"ROLLBACK_UNAVAILABLE")
        old_checkpoint,old_candidate=ch["checkpoint"],ch["candidate"]
        ch.update(checkpoint=ch["previous_checkpoint"],candidate=ch["previous_candidate"],previous_checkpoint=old_checkpoint,previous_candidate=old_candidate,sequence=ch["sequence"]+1,state="ROLLED_BACK",reason=b["reason"])
        self.put(c,"channel",key,ch);return ch

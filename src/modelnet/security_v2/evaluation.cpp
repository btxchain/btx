// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/evaluation.h>
#include <algorithm>
namespace modelnet::security {
    Json ReadLocalConfig(Database& db) {
        auto c=Parse(ReadFile(db.Root()/"local.json",MAX_RECORD,true));
        Fields(c, {
            "schema","workspaces","packages","host"
        },
        {
            "evaluation_plans","runtimes","identity","peer_identity","execution_policy","continuous_security","remote_work"
        });
        Require(Text(c,"schema")=="BTX/SecurityLocal/v1","SEC_LOCAL_VERSION");
        return c;
    }
    KeyPair LoadLocalIdentity(Database& db,const Policy& p,std::string_view role,int64_t now) {
        auto config=ReadLocalConfig(db);
        const auto& id=(role=="peer"&&config["peer_identity"].isObject())?config["peer_identity"]:config["identity"];
        Fields(id, {
            "public_key","secret_file"
        });
        KeyPair key;
        key.public_key=Unhex(Text(id,"public_key",PK_BYTES*2),PK_BYTES);
        const auto& principal=p.Find(KeyId(key.public_key),role,db,now);
        Require(principal.host==Text(config,"host",128),"SEC_LOCAL_HOST_ENROLLMENT");
        auto raw=ReadFile(NativePath(Text(id,"secret_file")),SK_BYTES*2+1,true);
        if(!raw.empty()&&raw.back()=='\n')raw.pop_back();
        key.secret_key=Unhex(raw,SK_BYTES);
        volatile char* erase=raw.data();
        for(size_t i=0; i<raw.size(); ++i)erase[i]=0;
        Require(key.secret_key.size()==SK_BYTES,"SEC_SECRET_KEY");
        auto probe=Object();
        probe.pushKV("key",KeyId(key.public_key));
        const auto signature=Unhex(Sign("receipt",probe,key.secret_key),SIG_BYTES);
        Require(Verify("receipt",probe,key.public_key,signature),"SEC_LOCAL_KEY_MISMATCH");
        return key;
    }
    std::string PlanId(const Json& p) {
        Fields(p, {
            "schema","suite","sample_commitment","gate","executable_sha384","sandbox",
            "input_sha384","expected_output_sha384","expected_output_bytes","cases",
            "memory_bytes","wall_ms","cpu_ms","output_bytes"
        });
        Require(Text(p,"schema")=="BTX/StaticEvaluationPlan/v1","SEC_PLAN_VERSION");
        for(auto field: {
            "suite","sample_commitment","executable_sha384","sandbox","input_sha384","expected_output_sha384"
        })
        DigestField(p,field);
        Require(DigestField(p,"sandbox")==StaticSandboxDigest(),"SEC_PLAN_SANDBOX");
        Require(UInt(p,"cases",10000000)>0,"SEC_PLAN_CASES");
        UInt(p,"expected_output_bytes",16*1024*1024);
        Text(p,"gate",64);
        return DomainHash("BTX/StaticEvaluationPlan/v1",Canonical(p));
    }
    PlanRun RunApprovedPlan(Database& db,const Policy& p,const KeyPair& key,
    const std::string& composition,const std::string& package,
    const std::string& request,const std::function<bool()>& allowed) {
        Require(IsHash(package)&&IsHash(request),"SEC_PLAN_REFERENCE");
        const auto local=ReadLocalConfig(db);
        Require(local["execution_policy"].isObject()&&Boolean(local["execution_policy"],"allow_evaluation"),
        "SEC_LOCAL_COMPUTE_NOT_GRANTED");
        const auto& entry=local["evaluation_plans"][package];
        Fields(entry, {
            "plan","executable","input_file"
        });
        const auto& plan=entry["plan"];
        Require(PlanId(plan)==package,"SEC_PLAN_ID");
        auto comp=db.Get(composition);
        Require(Text(comp,"kind")=="composition","SEC_COMPOSITION_KIND");
        p.Check(comp,"publisher",db,NowMs());
        ValidateComposition(comp["body"]);
        // This profile executes one self-contained static runtime. Evidence must
        // name those measured bytes, not an unrelated declared runtime label.
        Require(DigestField(comp["body"],"runtime")==DigestField(plan,"executable_sha384") &&
        DigestField(comp["body"],"sandbox")==StaticSandboxDigest(), "SEC_RUNTIME_MEASUREMENT_BINDING");
        const auto input=ReadFile(NativePath(Text(entry,"input_file")),65536,true);
        Require(Hash(input)==DigestField(plan,"input_sha384"),"SEC_PLAN_INPUT");
        // Frame includes verified model, tokenizer, configuration and template bytes;
        // the test binary cannot reopen an unverified model path later.
        auto frame=ResidentFrame(db,composition,input);
        SandboxLimits limits {
            UInt(plan,"memory_bytes",64ull<<30),UInt(plan,"wall_ms",600000),
            UInt(plan,"cpu_ms",600000),UInt(plan,"output_bytes",16*1024*1024)
        };
        const auto& cap=local["execution_policy"];
        Fields(cap, {
            "allow_evaluation","max_memory_bytes","max_wall_ms","max_cpu_ms"
        });
        Require(limits.memory_bytes<=UInt(cap,"max_memory_bytes",64ull<<30)&&
        limits.wall_ms<=UInt(cap,"max_wall_ms",600000)&&
        limits.cpu_ms<=UInt(cap,"max_cpu_ms",600000),"SEC_LOCAL_COMPUTE_LIMIT");
        Require(allowed(),"SEC_EXECUTION_REVOKED");
        auto run=RunStaticWorker(NativePath(Text(entry,"executable")),DigestField(plan,"executable_sha384"),
        frame,limits,allowed);
        PlanRun result;
        result.cases=UInt(plan,"cases",10000000);
        if(!run.dispatched||!run.enforced||run.cancelled)result.outcome="BLOCKED";
        else if(!run.error.empty()||Hash(run.output)!=DigestField(plan,"expected_output_sha384")||
        run.output.size()!=UInt(plan,"expected_output_bytes",16*1024*1024))result.outcome="FAIL";
        else result.outcome="PASS";
        result.reason=run.error;
        if(result.reason.empty()&&result.outcome=="FAIL")result.reason="SEC_EXPECTED_OUTPUT_MISMATCH";
        Require(allowed(),"SEC_EVIDENCE_RELEASE_REVOKED");
        const auto finished=NowMs();
        Json body=Object();
        body.pushKV("realm",p.realm);
        body.pushKV("policy_epoch",p.epoch);
        body.pushKV("job",DomainHash("BTX/ExecutionJob/v1",Hex(RandomBytes(32))));
        body.pushKV("request",request);
        body.pushKV("package",package);
        body.pushKV("composition",composition);
        body.pushKV("runtime",comp["body"]["runtime"]);
        body.pushKV("sandbox",StaticSandboxDigest());
        body.pushKV("outcome",result.outcome);
        body.pushKV("output_digest",Hash(run.output));
        body.pushKV("output_bytes",static_cast<uint64_t>(run.output.size()));
        body.pushKV("issued_ms",finished);
        body.pushKV("expires_ms",static_cast<uint64_t>(finished)+p.evidence_ttl_ms);
        body.pushKV("host",Text(local,"host",128));
        body.pushKV("dispatched",run.dispatched&&run.enforced);
        Json observed=Object();
        observed.pushKV("elapsed_ms",run.elapsed_ms);
        observed.pushKV("memory_bytes",limits.memory_bytes);
        observed.pushKV("wall_ms",limits.wall_ms);
        observed.pushKV("output_bytes",limits.output_bytes);
        observed.pushKV("exit_code",run.exit_code);
        observed.pushKV("physical_hosts_observed",1);
        body.pushKV("limits",observed);
        result.receipt=Envelope("receipt",body);
        AddSignature(result.receipt,key);
        ImportRecord(db,p,result.receipt,finished);
        return result;
    }
    Json EvaluateChallenge(Database& db,const std::string& challenge_id,int64_t now) {
        const auto p=Policy::Load(db,now);
        auto key=LoadLocalIdentity(db,p,"evaluator",now);
        const auto evaluator=KeyId(key.public_key);
        p.Find(evaluator,"worker",db,now);
        auto e=db.Get(challenge_id);
        Require(Text(e,"kind")=="challenge","SEC_CHALLENGE_KIND");
        p.Check(e,"coordinator",db,now);
        const auto& ch=e["body"];
        Require(DigestField(ch,"realm")==p.realm&&UInt(ch,"policy_epoch")==p.epoch&&
        UInt(ch,"issued_ms",INT64_MAX)<=static_cast<uint64_t>(now)&&
        UInt(ch,"expires_ms",INT64_MAX)>static_cast<uint64_t>(now),"SEC_CHALLENGE_EXPIRED");
        const auto candidate=DigestField(ch,"composition"),package=DigestField(ch,"package");
        const auto local=ReadLocalConfig(db);
        const auto& plan=local["evaluation_plans"][package]["plan"];
        Require(PlanId(plan)==package,"SEC_PLAN_NOT_INSTALLED");
        for(auto field: {
            "suite","sample_commitment","gate"
        })Require(Text(plan,field)==Text(ch,field),"SEC_TEST_PLAN_BINDING");
        {
            Database::Transaction tx(db);
            db.CheckClock(now);
            Require(db.Query("SELECT phase FROM evaluation_runs WHERE challenge=? AND evaluator=?", {
                challenge_id,evaluator
            }).empty(),
            "SEC_EVALUATION_ALREADY_ATTEMPTED");
            db.Exec("INSERT INTO evaluation_runs(challenge,evaluator,phase,lease_until) VALUES(?,?,'running',?)",
            {
                challenge_id,evaluator,std::to_string(UInt(ch,"expires_ms",INT64_MAX))
            });
            db.Event("evaluation-started",challenge_id,Object());
            tx.Commit();
        }
        auto allowed=[&]() {
            try {
                const auto current=Policy::Load(db,NowMs());
                current.Find(evaluator,"worker",db,NowMs());
                current.Find(evaluator,"evaluator",db,NowMs());
                return current.id==p.id&&db.Meta("runtime_available","1")=="1"&&db.Meta("paused","0")=="0"&&
                !db.AncestryRevoked(candidate,NowMs())&&!db.Revoked(challenge_id,NowMs())&&
                static_cast<uint64_t>(NowMs())<UInt(ch,"expires_ms",INT64_MAX);
            }
            catch(...) {
                return false;
            }
        };
        try {
            auto run=RunApprovedPlan(db,p,key,candidate,package,challenge_id,allowed);
            Json body=Object();
            body.pushKV("realm",p.realm);
            body.pushKV("policy_epoch",p.epoch);
            for(auto field: {
                "composition","campaign","suite","sample_commitment","gate"
            })body.pushKV(field,ch[field]);
            body.pushKV("challenge",challenge_id);
            body.pushKV("runtime",run.receipt["body"]["runtime"]);
            body.pushKV("sandbox",run.receipt["body"]["sandbox"]);
            body.pushKV("outcome",run.outcome);
            body.pushKV("cases",run.cases);
            body.pushKV("execution_receipt",RecordId(run.receipt));
            body.pushKV("output_digest",run.receipt["body"]["output_digest"]);
            const auto finished=NowMs();
            body.pushKV("issued_ms",finished);
            body.pushKV("expires_ms",static_cast<uint64_t>(finished)+p.evidence_ttl_ms);
            body.pushKV("host",Text(local,"host",128));
            body.pushKV("physical_host_evidence",Text(local,"host",128));
            body.pushKV("limitations",Strings( {
                "LOCAL_EXECUTION_ONLY","OWNER_ENROLLED_HOST_NOT_HARDWARE_ATTESTATION",
                "TEST_ADEQUACY_REQUIRES_INDEPENDENT_REVIEW"
            }));
            auto report=Envelope("evaluation",body);
            AddSignature(report,key);
            Require(allowed(),"SEC_EVIDENCE_RELEASE_REVOKED");
            ImportRecord(db,p,report,finished);
            Database::Transaction tx(db);
            db.Exec("UPDATE evaluation_runs SET phase=?,report=? WHERE challenge=? AND evaluator=?",
            {
                run.outcome,RecordId(report),challenge_id,evaluator
            });
            db.Event("evaluation-finished",RecordId(report),Object());
            tx.Commit();
            return report;
        }
        catch(...) {
            Database::Transaction tx(db);
            db.Exec("UPDATE evaluation_runs SET phase='blocked' WHERE challenge=? AND evaluator=?",
            {
                challenge_id,evaluator
            });
            db.Event("evaluation-blocked",challenge_id,Object());
            tx.Commit();
            throw;
        }
    }
    Json RunChannelCanary(Database& db,const std::string& channel,int64_t now) {
        const auto p=Policy::Load(db,now);
        auto key=LoadLocalIdentity(db,p,"worker",now);
        auto rows=db.Query("SELECT candidate,update_id,phase FROM channels WHERE name=?", {
            channel
        });
        Require(rows.size()==1&&rows[0][2]=="canary","SEC_NO_CANARY");
        const auto capsule_id=rows[0][0],update_id=rows[0][1];
        const auto admission=AdmitCapsule(db,p,capsule_id,now);
        auto config=ReadLocalConfig(db);
        const auto& runtime=config["runtimes"][admission.runtime];
        Fields(runtime, {
            "canary_package"
        });
        const auto package=DigestField(runtime,"canary_package");
        auto allowed=[&]() {
            try {
                const auto current=Policy::Load(db,NowMs());
                auto current_rows=db.Query("SELECT candidate,update_id,phase FROM channels WHERE name=?", {
                    channel
                });
                (void)AdmitCapsule(db,current,capsule_id,NowMs());
                return current.id==p.id&&db.Meta("runtime_available","1")=="1"&&db.Meta("paused","0")=="0"&&current_rows.size()==1&&
                current_rows[0][0]==capsule_id&&current_rows[0][1]==update_id&&current_rows[0][2]=="canary";
            }
            catch(...) {
                return false;
            }
        };
        auto run=RunApprovedPlan(db,p,key,admission.composition_id,package,update_id,allowed);
        if(run.outcome!="PASS") {
            Database::Transaction tx(db);
            db.Exec("UPDATE channels SET candidate='',phase='frozen' WHERE name=? AND candidate=?", {
                channel,capsule_id
            });
            db.Event("canary-failed",capsule_id,Object());
            tx.Commit();
            throw Error("SEC_CANARY_FAILED");
        }
        return run.receipt;
    }
}
// namespace modelnet::security

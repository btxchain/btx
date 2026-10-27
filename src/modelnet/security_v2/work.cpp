// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/work.h>
#include <modelnet/security_v2/mesh.h>
#include <algorithm>
#include <map>
#include <set>
namespace modelnet::security {
namespace {
void Tables(Database& db){
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_work_runs(work TEXT NOT NULL,worker TEXT NOT NULL,phase TEXT NOT NULL,receipt TEXT NOT NULL DEFAULT '',result TEXT NOT NULL DEFAULT '',PRIMARY KEY(work,worker)) WITHOUT ROWID");
}
std::string Host(const Json& local){return Text(local,"host",128);}
bool Listed(const Json& value,const std::string& name){
    const auto a=StringArray(value,128);return std::find(a.begin(),a.end(),name)!=a.end();
}
void Fresh(const Json& b,const Policy& p,int64_t now){
    Require(DigestField(b,"realm")==p.realm&&UInt(b,"policy_epoch")==p.epoch,"SEC_WORK_REALM");
    const auto issued=UInt(b,"issued_ms",INT64_MAX),expiry=UInt(b,"expires_ms",INT64_MAX);
    Require(issued<=static_cast<uint64_t>(now)&&expiry>static_cast<uint64_t>(now)&&
            expiry-issued<=p.evidence_ttl_ms,"SEC_WORK_EXPIRED");
}
}
Json ExecuteMeshWork(Database& db,const std::string& id,int64_t now){
    Tables(db);auto p=Policy::Load(db,now);auto e=db.Get(id);
    Require(Text(e,"kind")=="work","SEC_WORK_KIND");p.Check(e,"coordinator",db,now);
    const auto& b=e["body"];Fresh(b,p,now);
    auto local=ReadLocalConfig(db);const auto& policy=local["remote_work"];
    Require(policy.isObject()&&Boolean(policy,"enabled"),"SEC_WORK_LOCAL_CONSENT");
    const auto package=DigestField(b,"package"),composition=DigestField(b,"composition");
    Require(Listed(policy["packages"],package)&&Listed(policy["compositions"],composition),
            "SEC_WORK_UNAPPROVED_PACKAGE");
    auto me=LoadLocalIdentity(db,p,"worker",now);
    const auto worker=KeyId(me.public_key),host=Host(local);
    Require(Text(b,"target_host",128)==host||Text(b,"target_host",128)=="any","SEC_WORK_WRONG_HOST");
    const auto& entry=local["evaluation_plans"][package];
    Require(entry.isObject()&&PlanId(entry["plan"])==package,"SEC_WORK_PLAN_ABSENT");
    Require(DigestField(entry["plan"],"input_sha384")==DigestField(b,"input_sha384")&&
            DigestField(entry["plan"],"expected_output_sha384")==DigestField(b,"expected_output_sha384"),
            "SEC_WORK_INPUT_OR_OUTPUT_SUBSTITUTION");
    const auto max_bytes=UInt(b,"max_output_bytes",16*1024*1024);
    Require(max_bytes>0&&max_bytes<=16384&&UInt(entry["plan"],"expected_output_bytes",16*1024*1024)<=max_bytes,
            "SEC_WORK_OUTPUT_LIMIT");
    if(db.Meta("mesh_required","0")=="1"){
        const auto capsule=DigestField(b,"capsule");
        auto admission=AdmitCapsule(db,p,capsule,now);
        Require(admission.composition_id==composition,"SEC_WORK_CAPSULE");
        MeshRequireLive(db,p,capsule,now);
    }
    {
        Database::Transaction tx(db);db.CheckClock(now);
        Require(db.Query("SELECT work FROM mesh_work_runs WHERE work=? AND worker=?",{id,worker}).empty(),
                "SEC_WORK_REPLAY");
        Require(ParseUInt(db.Query("SELECT count(*) FROM mesh_work_runs")[0][0])<16384,"SEC_WORK_QUOTA");
        db.Exec("INSERT INTO mesh_work_runs(work,worker,phase) VALUES(?,?,'running')",{id,worker});
        db.Event("mesh-work-started",id,Object());tx.Commit();
    }
    auto allowed=[&](){
        try {
            auto fresh=Policy::Load(db,NowMs());
            fresh.Find(worker,"worker",db,NowMs());
            return fresh.id==p.id&&db.Meta("paused","0")=="0"&&
                   db.Meta("runtime_available","0")=="1"&&!db.AncestryRevoked(composition,NowMs())&&
                   !db.Revoked(id,NowMs())&&UInt(b,"expires_ms",INT64_MAX)>static_cast<uint64_t>(NowMs())&&
                   (db.Meta("mesh_required","0")!="1" || [&](){
                       MeshRequireLive(db,fresh,DigestField(b,"capsule"),NowMs());return true;
                   }());
        }catch(...){return false;}
    };
    try {
        auto run=RunApprovedPlan(db,p,me,composition,package,id,allowed);
        auto receipt_id=RecordId(run.receipt);
        Json rb=Object();rb.pushKV("realm",p.realm);rb.pushKV("policy_epoch",p.epoch);
        rb.pushKV("work",id);rb.pushKV("purpose",Text(b,"purpose"));
        rb.pushKV("composition",composition);rb.pushKV("package",package);
        rb.pushKV("receipt",receipt_id);rb.pushKV("host",host);
        rb.pushKV("outcome",run.outcome);rb.pushKV("output_sha384",run.receipt["body"]["output_digest"]);
        rb.pushKV("output_bytes",run.receipt["body"]["output_bytes"]);
        rb.pushKV("issued_ms",NowMs());rb.pushKV("expires_ms",static_cast<uint64_t>(NowMs())+p.evidence_ttl_ms);
        auto result=Envelope("result",rb);AddSignature(result,me);
        Require(allowed(),"SEC_WORK_OUTPUT_RELEASE_REVOKED");
        ImportRecord(db,p,result,NowMs());
        Database::Transaction tx(db);
        db.Exec("UPDATE mesh_work_runs SET phase=?,receipt=?,result=? WHERE work=? AND worker=?",
                {run.outcome,receipt_id,RecordId(result),id,worker});
        db.Event("mesh-work-finished",RecordId(result),Object());tx.Commit();
        return result;
    } catch(...) {
        db.Exec("UPDATE mesh_work_runs SET phase='blocked' WHERE work=? AND worker=?",{id,worker});
        throw;
    }
}
Json VerifyMeshWorkQuorum(Database& db,const std::string& id,int64_t now){
    auto p=Policy::Load(db,now);auto work=db.Get(id);
    Require(Text(work,"kind")=="work","SEC_WORK_KIND");p.Check(work,"coordinator",db,now);
    Require(!db.Revoked(id,now)&&!db.AncestryRevoked(DigestField(work["body"],"composition"),now),
            "SEC_WORK_QUARANTINE");
    const auto& wb=work["body"];Fresh(wb,p,now);
    std::set<std::string> keys,domains,hosts;std::string expected;
    for(const auto& row:db.Query("SELECT envelope FROM objects WHERE kind='result'")){
        auto result=Parse(row[0]);const auto& b=result["body"];
        if(DigestField(b,"work")!=id)continue;
        Fresh(b,p,now);
        Require(!db.Revoked(RecordId(result),now),"SEC_WORK_REVOKED");
        const auto signers=p.Check(result,"worker",db,now);
        Require(signers.size()==1,"SEC_WORK_RESULT_SIGNER");
        const auto key=signers[0];const auto& principal=p.Find(key,"worker",db,now);
        Require(keys.insert(key).second&&hosts.insert(principal.host).second,"SEC_WORK_DUPLICATE_HOST");
        Require(Text(b,"host")==principal.host&&Text(b,"purpose")==Text(wb,"purpose")&&
                DigestField(b,"composition")==DigestField(wb,"composition")&&
                DigestField(b,"package")==DigestField(wb,"package")&&Text(b,"outcome")=="PASS",
                "SEC_WORK_RESULT_BIND");
        auto receipt=db.Get(DigestField(b,"receipt"));
        Require(!db.Revoked(RecordId(receipt),now),"SEC_WORK_REVOKED");
        auto worker=p.Check(receipt,"worker",db,now);
        Require(worker.size()==1&&worker[0]==key,"SEC_WORK_RECEIPT_SIGNER");
        const auto& r=receipt["body"];
        Fresh(r,p,now);
        Require(Boolean(r,"dispatched")&&Text(r,"outcome")=="PASS"&&
                DigestField(r,"request")==id&&Text(r,"host")==principal.host&&
                DigestField(r,"composition")==DigestField(wb,"composition")&&
                DigestField(r,"package")==DigestField(wb,"package")&&
                DigestField(r,"output_digest")==DigestField(b,"output_sha384")&&
                UInt(r,"output_bytes")==UInt(b,"output_bytes"),"SEC_WORK_RECEIPT_BIND");
        const auto output=DigestField(b,"output_sha384");
        Require(output==DigestField(wb,"expected_output_sha384")&&
                UInt(b,"output_bytes")<=UInt(wb,"max_output_bytes"),
                "SEC_WORK_OUTPUT_SUBSTITUTION");
        if(expected.empty())expected=output;
        Require(output==expected,"SEC_WORK_DIVERGENT_OUTPUT");
        auto live=db.Query("SELECT seen_ms,epoch FROM mesh_live WHERE peer=?",{key});
        Require(live.size()==1&&ParseUInt(live[0][1])==p.epoch&&
                ParseUInt(live[0][0])<=static_cast<uint64_t>(now)&&
                static_cast<uint64_t>(now)-ParseUInt(live[0][0])<=30000,"SEC_WORK_PEER_EXPIRED");
        domains.insert(principal.domain);
    }
    Require(hosts.size()>=p.physical_hosts&&domains.size()>=p.evaluator_domains,"SEC_WORK_QUORUM");
    Json out=Object();out.pushKV("schema","BTX/WorkQuorum/v1");out.pushKV("work",id);
    out.pushKV("output_sha384",expected);out.pushKV("enrolled_hosts",static_cast<uint64_t>(hosts.size()));
    out.pushKV("enrolled_domains",static_cast<uint64_t>(domains.size()));
    out.pushKV("hardware_independence_verified",false);out.pushKV("actual_peer_execution_reported",true);
    out.pushKV("automatically_spent_atoms","0");return out;
}
} // namespace modelnet::security

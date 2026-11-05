// Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
// Signed local fixtures. Unsigned inert rows construct only the admission count.
#include <modelnet/security_v2/trust.h>
#include <chrono>
#include <functional>
#include <iostream>
#include <thread>
using namespace modelnet::security;
namespace {
void Check(bool ok,const char* why) { if(!ok)throw std::runtime_error(why); }
Json Sign(const std::string& kind,const Json& body,const KeyPair& a,const KeyPair* b=nullptr) {
    auto e=Envelope(kind,body);AddSignature(e,a);if(b)AddSignature(e,*b);return e;
}
Json Common(const std::string& realm,int64_t now,uint64_t ttl=60000) {
    auto b=Object();b.pushKV("realm",realm);b.pushKV("policy_epoch",1);b.pushKV("issued_ms",now);
    b.pushKV("expires_ms",static_cast<uint64_t>(now)+ttl);return b;
}
struct Temp {
    fs::path root=fs::temp_directory_path()/("btx-store-recovery-"+Hex(RandomBytes(12)));
    Temp(){EnsurePrivateDirectory(root);}
    ~Temp(){std::error_code ec;fs::remove_all(root,ec);}
};
struct Fixture {
    Temp temp;Database db{temp.root};
    KeyPair owner=GenerateKey(),second=GenerateKey(),worker=GenerateKey();
    std::string realm=Hash("store-recovery-test-realm");Json policy_record;Policy policy;
    explicit Fixture(uint64_t policy_ttl=3600000) {
        auto roots=Object();roots.pushKV("schema","BTX/SecurityRootPins/v1");
        roots.pushKV("keys",Strings({KeyId(owner.public_key)}));roots.pushKV("threshold",1);
        WritePrivate(temp.root/"root-pins.json",Canonical(roots));
        auto now=NowMs();auto b=Object();b.pushKV("realm",realm);b.pushKV("epoch",1);
        b.pushKV("issued_ms",now);b.pushKV("expires_ms",static_cast<uint64_t>(now)+policy_ttl);
        b.pushKV("release_threshold",2);b.pushKV("evaluator_domains",2);b.pushKV("physical_hosts",2);
        b.pushKV("evidence_ttl_ms",60000);b.pushKV("canary_ms",1000);b.pushKV("trial_limit",8);
        b.pushKV("gates",Strings({"external-controls","outcome","revocation","rollback","privacy","adversarial"}));
        auto principals=Array();
        auto add=[&](const KeyPair& key,const std::vector<std::string>& roles,const std::string& name){
            auto p=Object();p.pushKV("public_key",Hex(key.public_key));p.pushKV("roles",Strings(roles));
            p.pushKV("domain",name);p.pushKV("host",name);p.pushKV("transport_pin","");principals.push_back(p);
        };
        add(owner,{"owner","revoker"},"owner");add(second,{"revoker"},"second");
        add(worker,{"worker","evaluator"},"worker");b.pushKV("principals",principals);
        policy_record=Sign("policy",b,owner);InstallPolicy(db,policy_record,now);policy=Policy::Load(db,NowMs());
    }
    Json Evidence(const std::string& kind,int64_t now=NowMs(),uint64_t ttl=60000) {
        auto b=Common(realm,now,ttl);
        for(auto name:{"composition","runtime","sandbox","output_digest"})b.pushKV(name,Hash(name));
        b.pushKV("host","worker");b.pushKV("outcome","PASS");
        if(kind=="receipt") {
            b.pushKV("job",Hash(Hex(RandomBytes(12))));b.pushKV("request",Hash("request"));
            b.pushKV("package",Hash("package"));b.pushKV("output_bytes",1);
            b.pushKV("limits",Object());b.pushKV("dispatched",true);
        } else {
            for(auto name:{"challenge","campaign","suite","sample_commitment","execution_receipt"})b.pushKV(name,Hash(name));
            b.pushKV("gate","privacy");b.pushKV("cases",1);b.pushKV("physical_host_evidence","worker");
            b.pushKV("limitations",Strings({"LOCAL_SYNTHETIC_COMPONENT_FIXTURE"}));
            b.pushKV("challenge",Hash(Hex(RandomBytes(12))));
        }
        return Sign(kind,b,worker);
    }
    Json Revocation(const std::string& subject) {
        auto b=Common(realm,NowMs());b.pushKV("subject",subject);b.pushKV("sequence",1);
        b.pushKV("reason","local recovery regression");return Sign("revocation",b,owner,&second);
    }
    Json NextPolicy(){auto b=policy_record["body"];b.pushKV("epoch",2);return Sign("policy",b,owner);}
};
uint64_t Count(Database& db){return ParseUInt(db.Query("SELECT count(*) FROM objects")[0][0]);}
void Fill(Database& db) {
    Database::Transaction tx(db);
    for(uint64_t i=Count(db);i<16384;++i){auto b=Object();b.pushKV("unsigned_quota_fixture",i);db.Put(Envelope("control",b));}
    tx.Commit();Check(Count(db)==16384,"fixture missed exact ordinary quota");
}
// Adapt the old proof's complete paginated table snapshot; no clock/journal exemption.
std::string Snapshot(Database& db) {
    auto out=Object();
    for(const auto& t:db.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")) {
        auto name=t[0];std::string order;
        for(const auto& c:db.Query("PRAGMA table_info(\""+name+"\")")){if(!order.empty())order+=",";order+="\""+c[1]+"\"";}
        std::string bytes;uint64_t count=0;
        while(true){auto rows=db.Query("SELECT * FROM \""+name+"\" ORDER BY "+order+" LIMIT 256 OFFSET ?",{std::to_string(count)});
            if(rows.empty())break;
            for(const auto& row:rows)for(const auto& col:row)bytes+=std::to_string(col.size())+":"+col;
            count+=rows.size();}
        auto state=Object();state.pushKV("rows",count);state.pushKV("hash",Hash(bytes));out.pushKV(name,state);
    }
    return Canonical(out);
}
template<typename F> void Refuse(Database& db,F fn,const std::string& code) {
    auto before=Snapshot(db);bool refused=false;
    try{fn();}catch(const Error& e){if(e.code!=code)throw std::runtime_error("expected "+code+", received "+e.code);refused=true;}
    Check(refused,"expected refusal");Check(before==Snapshot(db),"refusal changed database state");
}
void WaitPast(uint64_t expiry){while(static_cast<uint64_t>(NowMs())<=expiry)std::this_thread::sleep_for(std::chrono::milliseconds(5));}
void LiveControls() {
    Fixture f;
    for(const std::string kind:{"receipt","evaluation"}) {
        auto e=f.Evidence(kind);unsigned calls=0;
        ImportCurrentEvidence(f.db,f.policy,e,[&]{++calls;return true;});
        Check(calls==1&&f.db.Has(RecordId(e)),"valid current evidence failed");
        Check(f.db.Query("SELECT visibility FROM objects WHERE id=?",{RecordId(e)})[0][0]=="private","live evidence became public");
        auto denied=f.Evidence(kind);calls=0;
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,denied,[&]{++calls;return false;});},"SEC_EVIDENCE_RELEASE_REVOKED");
        Check(calls==1,"release gate callback missed");
        auto expired=f.Evidence(kind,NowMs()-2000,1000);calls=0;
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,expired,[&]{++calls;return true;});},"SEC_EXPIRED_OR_FUTURE");
        Check(calls==0,"expired evidence reached callback");
        auto wrong=f.policy;wrong.id=Hash("not-current-policy");calls=0;
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,wrong,denied,[&]{++calls;return true;});},"SEC_POLICY_CHANGED");
        Check(calls==0,"wrong policy reached callback");
        auto body=denied["body"];body.pushKV("policy_epoch",2);auto binding=Sign(kind,body,f.worker);calls=0;
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,binding,[&]{++calls;return true;});},"SEC_POLICY_BINDING");
        Check(calls==0,"wrong epoch reached callback");
        auto role=Sign(kind,denied["body"],f.owner);calls=0;
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,role,[&]{++calls;return true;});},"SEC_SIGNATURE_THRESHOLD");
        Check(calls==0,"wrong role reached callback");
        auto short_lived=f.Evidence(kind,NowMs(),1000);auto expiry=UInt(short_lived["body"],"expires_ms");calls=0;
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,short_lived,[&]{++calls;Check(static_cast<uint64_t>(NowMs())<expiry,"evidence expired before callback");WaitPast(expiry);return true;});},"SEC_EXPIRED_OR_FUTURE");
        Check(calls==1,"commit-expiry control missed initial valid path");
        auto revoked=f.Evidence(kind);auto rev=f.Revocation(RecordId(revoked));ImportRecord(f.db,f.policy,rev,NowMs());calls=0;
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,revoked,[&]{++calls;return true;});},"SEC_RECORD_REVOKED");
        Check(calls==0,"revoked record reached callback");
    }
    auto rev=f.Revocation(KeyId(f.worker.public_key));ImportRecord(f.db,f.policy,rev,NowMs());
    auto denied=f.Evidence("receipt");
    Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,denied,[]{return true;});},"SEC_SIGNER_REVOKED");
    Check(f.db.VerifyJournal(),"valid-control journal broken");
}
void PolicyCommitExpiry() {
    Fixture f(1000);auto e=f.Evidence("receipt");unsigned calls=0;
    Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,e,[&]{++calls;Check(static_cast<uint64_t>(NowMs())<f.policy.expires,"policy expired before callback");WaitPast(f.policy.expires);return true;});},"SEC_EXPIRED_OR_FUTURE");
    Check(calls==1,"policy commit-expiry control missed valid path");
}
void ChangedPolicy() {
    Fixture f;auto e=f.Evidence("receipt");auto next=f.NextPolicy();InstallPolicy(f.db,next,NowMs());
    unsigned calls=0;
    Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,e,[&]{++calls;return true;});},"SEC_POLICY_CHANGED");
    Check(calls==0,"stale expected policy reached callback");
    auto current=Policy::Load(f.db,NowMs());
    Refuse(f.db,[&]{ImportCurrentEvidence(f.db,current,e,[&]{++calls;return true;});},"SEC_POLICY_BINDING");
    Check(calls==0,"old epoch evidence reached callback");
}
void PolicyRecovery() {
    Fixture f;Fill(f.db);auto next=f.NextPolicy();InstallPolicy(f.db,next,NowMs());
    Check(Count(f.db)==16385&&f.db.Meta("active_policy")==RecordId(next),"policy did not recover at cap");
    Check(f.db.Meta("policy_epoch")=="2"&&f.db.VerifyJournal(),"policy metadata/journal incorrect");
    Refuse(f.db,[&]{InstallPolicy(f.db,f.policy_record,NowMs());},"SEC_POLICY_ROLLBACK");
}
void RevocationRecovery() {
    Fixture f;auto subject=f.Evidence("receipt");ImportCurrentEvidence(f.db,f.policy,subject,[]{return true;});Fill(f.db);
    for(const std::string kind:{"receipt","evaluation"}){auto e=f.Evidence(kind);unsigned calls=0;
        Check(!f.db.Has(RecordId(e)),"quota probe used an existing ID");
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,e,[&]{++calls;return true;});},"SEC_OBJECT_QUOTA");
        Check(calls==1,"quota probe stopped before accepted authority path");}
    auto rev=f.Revocation(RecordId(subject));ImportRecord(f.db,f.policy,rev,NowMs(),true);
    Check(Count(f.db)==16385&&f.db.Revoked(RecordId(subject),NowMs()),"revocation did not recover at cap");
    for(const std::string kind:{"receipt","evaluation"}){auto e=f.Evidence(kind);unsigned calls=0;
        Check(!f.db.Has(RecordId(e)),"quota probe used an existing ID");
        Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,e,[&]{++calls;return true;});},"SEC_OBJECT_QUOTA");
        Check(calls==1,"quota probe stopped before accepted authority path");}
    Refuse(f.db,[&]{ImportCurrentEvidence(f.db,f.policy,subject,[]{return true;});},"SEC_RECORD_REVOKED");
    Check(f.db.VerifyJournal(),"recovered revocation journal broken");
}
}
int main() {
    unsigned failed=0;
    for(const auto& [name,test]:std::vector<std::pair<std::string,std::function<void()>>>{
        {"current-evidence-authority-and-fresh-commit",LiveControls},{"policy-expiry-at-commit",PolicyCommitExpiry},
        {"changed-current-policy",ChangedPolicy},{"policy-recovery-at-ordinary-cap",PolicyRecovery},{"revocation-recovery-with-ordinary-evidence-quota",RevocationRecovery}}) {
        try{test();std::cout<<"PASS "<<name<<std::endl;}
        catch(const std::exception& e){++failed;std::cerr<<"FAIL "<<name<<": "<<e.what()<<std::endl;}
    }
    return failed?1:0;
}

// Copyright (c) 2026 The BTX developers. MIT license.
// All identities, credentials and model tensors below are synthetic fixtures.
// Two signer identities on this test host do NOT qualify two physical hosts.
#include <modelnet/security_v2/lifecycle.h>
#include <modelnet/security_v2/broker.h>
#include <modelnet/security_v2/mesh.h>
#include <modelnet/security_v2/work.h>
#include <tuple>
#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <thread>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif
using namespace modelnet::security;
namespace {
struct Harness {
    size_t passed{0},failed{0};Json results=Array();
    template<class F> void Test(const std::string& name,F f) {
        Json row=Object();row.pushKV("name",name);
        try{f();++passed;row.pushKV("status","PASS");std::cout<<"PASS "<<name<<'\n';}
        catch(const std::exception& e){++failed;row.pushKV("status","FAIL");row.pushKV("error",e.what());std::cerr<<"FAIL "<<name<<": "<<e.what()<<'\n';}
        results.push_back(row);
    }
};
void Check(bool value,const char* text){if(!value)throw std::runtime_error(text);}
template<class F> void Reject(F f,std::string_view expected={}) {
    try{f();}catch(const Error& e){if(!expected.empty()&&e.code!=expected)throw std::runtime_error("expected "+std::string(expected)+", received "+e.code);return;}
    throw std::runtime_error("expected refusal");
}
struct Temp {
    fs::path root;
    Temp(){root=fs::canonical(fs::temp_directory_path())/("btx-security-test-"+Hex(RandomBytes(12)));EnsurePrivateDirectory(root);}
    ~Temp(){std::error_code ec;fs::remove_all(root,ec);}
};
const std::vector<std::string> GATES{"external-controls","outcome","revocation","rollback","privacy","adversarial"};
Json Signed(const std::string& kind,const Json& body,const KeyPair& a,const KeyPair* b=nullptr) {
    auto e=Envelope(kind,body);AddSignature(e,a);if(b)AddSignature(e,*b);return e;
}
Json Common(const std::string& realm,uint64_t epoch,int64_t now,uint64_t ttl=60000) {
    auto b=Object();b.pushKV("realm",realm);b.pushKV("policy_epoch",epoch);b.pushKV("issued_ms",now);b.pushKV("expires_ms",static_cast<uint64_t>(now)+ttl);return b;
}
Json signed_records=Array();
struct Fixture {
    Temp temp;fs::path root;Database db;
    KeyPair owner=GenerateKey(),publisher=GenerateKey(),second=GenerateKey(),alice=GenerateKey(),bob=GenerateKey();
    std::string realm=Hash("test realm"),session=Hex(RandomBytes(32)),runtime=Hash("test runtime"),schema=Hash("tool schema");
    int64_t now=NowMs()-5000;Json policy_record,local;
    Policy policy;
    fs::path probe;
    std::string capsule,composition;std::vector<std::string> evaluations;
    explicit Fixture(fs::path executable={},bool common_domain=false,int64_t offset=5000):root(temp.root/"security"),db(root),probe(std::move(executable)) {
        now=NowMs()-offset;
        if(!probe.empty())runtime=Hash(ReadFile(probe,128*1024*1024));
        auto pins=Object();pins.pushKV("schema","BTX/SecurityRootPins/v1");pins.pushKV("keys",Strings({KeyId(owner.public_key)}));pins.pushKV("threshold",1);WritePrivate(root/"root-pins.json",Canonical(pins));
        Json b=Object();b.pushKV("realm",realm);b.pushKV("epoch",1);b.pushKV("issued_ms",now);b.pushKV("expires_ms",now+3600000);
        b.pushKV("release_threshold",2);b.pushKV("evaluator_domains",2);b.pushKV("physical_hosts",2);b.pushKV("evidence_ttl_ms",60000);
        b.pushKV("canary_ms",1000);b.pushKV("trial_limit",8);b.pushKV("gates",Strings(GATES));Json principals=Array();
        auto principal=[&](const KeyPair& key,std::vector<std::string> roles,std::string domain,std::string host,std::string pin="") {
            Json p=Object();p.pushKV("public_key",Hex(key.public_key));p.pushKV("roles",Strings(roles));p.pushKV("domain",domain);p.pushKV("host",host);p.pushKV("transport_pin",pin);principals.push_back(p);
        };
        principal(owner,{"owner","release","revoker","coordinator","witness","peer"},"owner","owner-host",Hash("pin-owner"));
        principal(publisher,{"publisher"},"author","publisher-host");principal(second,{"release","revoker"},"release","release-host");
        principal(alice,{"evaluator","worker","peer"},"eval-a","host-a",Hash("pin-a"));
        principal(bob,{"evaluator","worker","peer"},common_domain?"eval-a":"eval-b","host-b",Hash("pin-b"));
        b.pushKV("principals",principals);policy_record=Signed("policy",b,owner);InstallPolicy(db,policy_record,now);signed_records.push_back(policy_record);policy=Policy::Load(db,now);
        EnsurePrivateDirectory(temp.root/"workspace");WritePrivate(temp.root/"workspace"/"source.txt","hello safe workspace\n");
        WritePrivate(temp.root/"workspace"/".env","SYNTHETIC_DECOY=not-a-real-secret\n");
        local=Object();local.pushKV("schema","BTX/SecurityLocal/v1");local.pushKV("host","host-a");auto work=Object();work.pushKV("code",(temp.root/"workspace").string());local.pushKV("workspaces",work);
        local.pushKV("packages",Object());local.pushKV("evaluation_plans",Object());local.pushKV("runtimes",Object());
        auto identity=Object();identity.pushKV("public_key",Hex(alice.public_key));identity.pushKV("secret_file",(root/"worker.key").string());local.pushKV("identity",identity);WritePrivate(root/"worker.key",Hex(alice.secret_key));
        auto compute=Object();compute.pushKV("allow_evaluation",true);compute.pushKV("max_memory_bytes",512*1024*1024);compute.pushKV("max_wall_ms",5000);compute.pushKV("max_cpu_ms",4000);local.pushKV("execution_policy",compute);SaveLocal();
        composition=MakeComposition("base");capsule=MakeEvidence(composition);
    }
    void SaveLocal(){WritePrivate(root/"local.json",Canonical(local),true);}
    std::string Import(const Json& e){ImportRecord(db,policy,e,now);signed_records.push_back(e);return RecordId(e);}
    Json Context(const std::string& c={}) {auto x=Object();x.pushKV("realm",realm);x.pushKV("composition",c.empty()?composition:c);x.pushKV("runtime",runtime);x.pushKV("tool_schema",schema);x.pushKV("session",session);return x;}
    std::string MakeComposition(const std::string& version,const std::vector<std::string>& parents={}) {
        auto b=Object();b.pushKV("realm",realm);b.pushKV("policy_epoch",1);b.pushKV("runtime",runtime);b.pushKV("sandbox",StaticSandboxDigest());b.pushKV("tool_schema",schema);b.pushKV("system_prompt",Hash("fixed system prompt"));b.pushKV("parents",Strings(parents));b.pushKV("contributors",Strings({KeyId(publisher.public_key)}));b.pushKV("license","MIT-test-fixture");b.pushKV("architecture","synthetic-fixture-not-an-LLM");b.pushKV("visibility","public");
        auto files=Array();const auto source=temp.root/("source-"+version);EnsurePrivateDirectory(source);
        const std::vector<std::pair<std::string,std::string>> components{{"weights.safetensors","weights"},{"tokenizer.json","tokenizer"},{"config.json","config"},{"chat.txt","chat_template"}};
        for(const auto& [path,role]:components) {
            std::string bytes=role=="weights"?std::string("synthetic tensors ")+version:std::string("{} ")+version;
            WritePrivate(source/path,bytes);auto f=Object();f.pushKV("path",path);f.pushKV("role",role);f.pushKV("sha384",Hash(bytes));f.pushKV("bytes",static_cast<uint64_t>(bytes.size()));files.push_back(f);
        }
        b.pushKV("files",files);auto e=Signed("composition",b,publisher);auto id=Import(e);ImportResident(db,policy,id,source,1024*1024,now);return id;
    }
    Json Challenge(const std::string& c,const std::string& gate,std::string package={}) {
        auto b=Common(realm,1,now);b.pushKV("composition",c);b.pushKV("campaign",Hash("campaign "+gate));b.pushKV("suite",Hash("suite "+gate));b.pushKV("sample_commitment",Hash("samples "+gate));b.pushKV("package",package.empty()?Hash("test package "+gate):package);b.pushKV("gate",gate);b.pushKV("trial_limit",8);return Signed("challenge",b,owner);
    }
    Json Receipt(const std::string& c,const std::string& request,const std::string& package,
                 const KeyPair& key,const std::string& host,int64_t timestamp,std::string output=Hash("output")) {
        auto b=Common(realm,1,timestamp);b.pushKV("job",Hash(Hex(RandomBytes(16))));b.pushKV("request",request);b.pushKV("package",package);b.pushKV("composition",c);b.pushKV("runtime",runtime);b.pushKV("sandbox",StaticSandboxDigest());b.pushKV("outcome","PASS");b.pushKV("output_digest",output);b.pushKV("output_bytes",100);b.pushKV("host",host);b.pushKV("limits",Object());b.pushKV("dispatched",true);return Signed("receipt",b,key);
    }
    Json Evaluation(const Json& challenge,const KeyPair& key,const std::string& host,std::string outcome="PASS") {
        const auto& ch=challenge["body"];const auto challenge_id=RecordId(challenge);
        const auto receipt=Receipt(Text(ch,"composition"),challenge_id,Text(ch,"package"),key,host,now);
        auto receipt_id=Import(receipt);auto b=Common(realm,1,now);
        for(auto field:{"composition","campaign","suite","sample_commitment","gate"})b.pushKV(field,ch[field]);
        b.pushKV("challenge",challenge_id);b.pushKV("runtime",runtime);b.pushKV("sandbox",StaticSandboxDigest());b.pushKV("outcome",outcome);b.pushKV("cases",50);b.pushKV("execution_receipt",receipt_id);b.pushKV("output_digest",receipt["body"]["output_digest"]);b.pushKV("host",host);b.pushKV("physical_host_evidence",host);b.pushKV("limitations",Strings({"SYNTHETIC_ATTESTATION_FIXTURE_ONE_PHYSICAL_TEST_HOST"}));return Signed("evaluation",b,key);
    }
    std::string Capsule(const std::string& c,const std::vector<std::string>& reports,uint64_t ttl=60000) {
        auto b=Common(realm,1,now,ttl);b.pushKV("composition",c);b.pushKV("evaluations",Strings(reports));b.pushKV("profile","restricted-tools");return Import(Signed("capsule",b,owner,&second));
    }
    std::string MakeEvidence(const std::string& c) {
        std::vector<std::string> reports;
        for(const auto& gate:GATES){auto ch=Challenge(c,gate);Import(ch);reports.push_back(Import(Evaluation(ch,alice,"host-a")));reports.push_back(Import(Evaluation(ch,bob,"host-b")));}
        evaluations=reports;return Capsule(c,reports);
    }
    std::string Grant(unsigned calls=4) {
        auto b=Common(realm,1,now);b.pushKV("composition",composition);b.pushKV("channel","");b.pushKV("capsule",capsule);b.pushKV("runtime",runtime);b.pushKV("tool_schema",schema);b.pushKV("session",session);b.pushKV("workspace","code");b.pushKV("tools",Strings({"read","hash","write-new","run-static"}));b.pushKV("read_paths",Strings({"source.txt","link.txt"}));b.pushKV("write_paths",Strings({"new.txt"}));std::vector<std::string> packages;for(const auto& x:local["packages"].getKeys())packages.push_back(x);b.pushKV("packages",Strings(packages));b.pushKV("max_calls",calls);b.pushKV("max_bytes",262144);b.pushKV("per_action_bytes",65536);return Import(Signed("grant",b,owner));
    }
    void Revoke(const std::string& id){auto b=Common(realm,1,now);b.pushKV("subject",id);b.pushKV("sequence",1);b.pushKV("reason","test incident");auto e=Signed("revocation",b,owner,&second);ImportRecord(db,Policy::Load(db,now),e,now);signed_records.push_back(e);}
    Json ReadRequest(){auto r=Object();r.pushKV("tool","read");r.pushKV("path","source.txt");return r;}
    std::string InstallProbePackage(){auto p=Object();p.pushKV("executable",probe.string());p.pushKV("sha384",Hash(ReadFile(probe,128*1024*1024)));p.pushKV("sandbox",StaticSandboxDigest());p.pushKV("wall_ms",1000);p.pushKV("cpu_ms",1000);p.pushKV("memory_bytes",256*1024*1024);const auto id=DomainHash("BTX/LocalStaticPackage/v1",Canonical(p));auto packages=local["packages"];packages.pushKV(id,p);local.pushKV("packages",packages);SaveLocal();return id;}
    Json FollowMandate(std::string runtime_id={}){auto b=Common(realm,1,now);b.pushKV("channel","coding/stable");b.pushKV("profile","restricted-tools");b.pushKV("runtimes",Strings({runtime_id.empty()?runtime:runtime_id}));b.pushKV("tool_schemas",Strings({schema}));b.pushKV("automatic_follow",true);return Signed("mandate",b,owner);}
    Json Channel(unsigned seq,const std::string& cap,std::string previous=""){auto b=Common(realm,1,now);b.pushKV("name","coding/stable");b.pushKV("sequence",seq);b.pushKV("capsule",cap);b.pushKV("previous",previous);return Signed("channel",b,owner,&second);}
};
// Canary receipts are signed synthetic attestations, not native sandbox executions.
std::string InstallSyntheticPlan(Fixture& f) {
    auto p=Object();p.pushKV("schema","BTX/StaticEvaluationPlan/v1");
    for(auto k:{"suite","sample_commitment","executable_sha384","input_sha384","expected_output_sha384"})p.pushKV(k,Hash(k));
    p.pushKV("gate","adversarial");p.pushKV("sandbox",StaticSandboxDigest());p.pushKV("expected_output_bytes",100);
    p.pushKV("cases",1);p.pushKV("memory_bytes",256*1024*1024);p.pushKV("wall_ms",2000);p.pushKV("cpu_ms",1000);p.pushKV("output_bytes",65536);
    const auto id=PlanId(p);auto e=Object();e.pushKV("plan",p);auto plans=Object();plans.pushKV(id,e);f.local.pushKV("evaluation_plans",plans);
    auto r=Object();r.pushKV("canary_package",id);auto runtimes=Object();runtimes.pushKV(f.runtime,r);f.local.pushKV("runtimes",runtimes);f.SaveLocal();return id;
}
std::string Canary(Fixture& f,const std::string& c,const std::string& update,const std::string& plan,const KeyPair& signer,int64_t t) {
    return f.Import(f.Receipt(c,update,plan,signer,"host-a",t,Hash("expected_output_sha384")));
}
void Observe(Fixture& f,Lifecycle& l,const std::string& c,const std::string& u,const std::string& p,int64_t t) {
    f.now=t;l.Observe("coding/stable",Canary(f,c,u,p,f.alice,t),t);
}
struct Active {
    Fixture f;Lifecycle l;int64_t base;std::string plan,mandate,old,first;
    explicit Active(bool expires=false,int64_t offset=5000):f({},false,offset),l(f.db),base(f.now) {
        plan=InstallSyntheticPlan(f);mandate=f.Import(f.FollowMandate());l.Follow(mandate,f.now);
        old=expires?f.Capsule(f.composition,f.evaluations,1500):f.capsule;
        first=f.Import(f.Channel(1,old));l.Stage(first,base);Observe(f,l,f.composition,first,plan,base);
        Observe(f,l,f.composition,first,plan,base+1000);l.Activate("coding/stable",f.now);
        Check(Text(l.Status()[0],"phase")=="active","initial valid activation");
    }
    std::string Next(const std::string& c,const std::string& cap) {
        auto u=f.Import(f.Channel(2,cap,old));l.Stage(u,f.now);Observe(f,l,c,u,plan,f.now);return u;
    }
};
void Phase(Database& db,const std::string& p,const char* message) {Check(Text(Lifecycle(db).Status()[0],"phase")==p,message);}
std::string PermitPhase(Database& db,const Json& permit) {return db.Query("SELECT phase FROM permits WHERE id=?",{Text(permit,"permit")})[0][0];}
}
int main(int argc,char** argv) {
    Harness h;
    h.Test("first-freeze-safety-and-unrelated-permit-repeat-reopen",[]{
        Active a(true);auto& f=a.f;Broker b(f.db,std::string(64,'a'));auto grant=f.Grant(20);auto context=f.Context(),request=f.ReadRequest();
        f.now=a.base+1499;auto before=b.Prepare(grant,context,request,f.now);
        f.now=a.base+2000;a.l.Tick(f.now);Phase(f.db,"frozen","expired active not frozen");
        Check(PermitPhase(f.db,before)=="revoked","first freeze did not revoke prepared permit");
        Check(!b.CanRelease(grant,f.Context(Hash("other composition")),request,f.now),"wrong context accepted");
        f.now+=1;auto after=b.Prepare(grant,context,request,f.now);a.l.Tick(f.now);
        const auto after_repeat=PermitPhase(f.db,after);
        {Database reopened(f.root);Lifecycle(reopened).Tick(f.now);Check(PermitPhase(reopened,after)==after_repeat,"reopen changed repeated-incident permit phase");}
        auto result=b.Execute(Text(after,"secret"),context,request,f.now);Check(Boolean(result,"ok")&&Boolean(result,"dispatched"),"unrelated permit did not execute read");
        Check(after_repeat=="prepared","repeated frozen Tick revoked unrelated newly prepared permit");
        Check(Text(result,"output_digest")==Hash("hello safe workspace\n"),"wrong read bytes");
        auto stale=f.Channel(4,a.old,a.old);Reject([&]{a.l.Stage(f.Import(stale),f.now);},"SEC_EXPIRED_OR_FUTURE");
    });
    h.Test("successor-survives-repeat-reopen-and-activates-with-real-binding",[]{
        Active a(true);auto& f=a.f;f.now=a.base+2000;a.l.Tick(f.now);Phase(f.db,"frozen","initial freeze missing");
        f.now+=1;auto c=f.MakeComposition("successor");auto cap=f.MakeEvidence(c);auto update=a.Next(c,cap);
        Broker b(f.db,std::string(64,'b'));auto direct=f.Grant(20);auto grant_body=f.db.Get(direct)["body"];grant_body.pushKV("composition","");grant_body.pushKV("capsule","");grant_body.pushKV("channel","coding/stable");auto channel_grant=f.Import(Signed("grant",grant_body,f.owner));
        Check(!b.CanRelease(channel_grant,f.Context(),f.ReadRequest(),f.now),"quarantined old active dispatchable");
        a.l.Tick(f.now);Check(a.l.Status()[0]["candidate_capsule"].get_str()==cap&&Text(a.l.Status()[0],"phase")=="canary","repeated expired-active Tick destroyed staged valid successor");
        {Database reopened(f.root);Lifecycle l(reopened);l.Tick(f.now);Check(l.Status()[0]["candidate_capsule"].get_str()==cap,"reopen lost staged successor");}
        f.now+=1000;Reject([&]{a.l.Activate("coding/stable",f.now);},"SEC_CANARY_SAMPLES");Observe(f,a.l,c,update,a.plan,f.now);a.l.Tick(f.now);
        Check(Text(a.l.Status()[0],"active_capsule")==cap&&Text(a.l.Status()[0],"phase")=="active","successor activation not recovered");
        auto permit=b.Prepare(channel_grant,f.Context(c),f.ReadRequest(),f.now);auto result=b.Execute(Text(permit,"secret"),f.Context(c),f.ReadRequest(),f.now);
        Check(Boolean(result,"ok")&&Boolean(result,"dispatched"),"recovered channel read failed");
        Reject([&]{b.Prepare(channel_grant,f.Context(),f.ReadRequest(),f.now);},"SEC_GENERATION_CHANGED");
        auto bad_previous=f.Import(f.Channel(3,cap,a.old));Reject([&]{a.l.Stage(bad_previous,f.now);},"SEC_CHANNEL_PREVIOUS");
        f.Revoke(cap);a.l.Tick(f.now);Check(Text(a.l.Status()[0],"phase")=="frozen","new generation incident suppressed by old quarantine");
    });
    h.Test("ordinary-canary-active-incident-still-freezes",[]{
        Active a;auto& f=a.f;f.now=a.base+1001;auto c=f.MakeComposition("ordinary");auto cap=f.MakeEvidence(c);a.Next(c,cap);f.Revoke(a.old);a.l.Tick(f.now);
        Phase(f.db,"frozen","new ordinary canary active failure bypassed");Check(a.l.Status()[0]["candidate_capsule"].get_str().empty(),"unsafe ordinary candidate survived initial incident");
    });
    h.Test("recovery-still-checks-owner-candidate-and-canary",[]{
        Active a(true);auto& f=a.f;f.now=a.base+2000;a.l.Tick(f.now);f.now+=1;auto c=f.MakeComposition("control");auto cap=f.MakeEvidence(c);
        auto narrow=f.Import(f.FollowMandate(Hash("unapproved runtime")));a.l.Follow(narrow,f.now);auto blocked=f.Import(f.Channel(2,cap,a.old));Reject([&]{a.l.Stage(blocked,f.now);},"SEC_UPDATE_AUTHORITY_EXPANSION");a.l.Follow(a.mandate,f.now);auto u=a.Next(c,cap);
        Reject([&]{a.l.Activate("coding/stable",f.now);},"SEC_CANARY_DURATION");
        auto wrong=Canary(f,c,Hash("wrong update"),a.plan,f.alice,f.now);Reject([&]{a.l.Observe("coding/stable",wrong,f.now);},"SEC_CANARY_GENERATION");
        Observe(f,a.l,c,u,a.plan,f.now+1000);auto observation=f.db.Query("SELECT receipt FROM observations ORDER BY at_ms LIMIT 1")[0][0];f.Revoke(observation);Reject([&]{a.l.Activate("coding/stable",f.now);},"SEC_CANARY_REVOKED");
        f.Revoke(cap);a.l.Tick(f.now);Check(a.l.Status()[0]["candidate_capsule"].get_str().empty(),"revoked candidate survived");
        f.now+=1;
        auto cap2=f.Capsule(c,f.evaluations);auto body=f.db.Get(u)["body"];body.pushKV("sequence",3);body.pushKV("capsule",cap2);auto next=f.Import(Signed("channel",body,f.owner,&f.second));a.l.Stage(next,f.now);
        f.Revoke(a.mandate);a.l.Tick(f.now);Phase(f.db,"frozen","revoked owner mandate bypassed");Check(a.l.Status()[0]["candidate_capsule"].get_str().empty(),"candidate survived owner revoke");
        auto forbidden=f.Import(f.Channel(4,cap2,a.old));Reject([&]{a.l.Stage(forbidden,f.now);},"SEC_FOLLOW_MANDATE");
    });
    h.Test("qualified-previous-rolls-back-and-sequence-does-not-reset",[]{
        Active a;auto& f=a.f;f.now=a.base+1001;auto c=f.MakeComposition("rollback");auto cap=f.MakeEvidence(c);auto u=a.Next(c,cap);Observe(f,a.l,c,u,a.plan,a.base+2001);a.l.Activate("coding/stable",f.now);
        f.Revoke(cap);a.l.Tick(f.now);Check(Text(a.l.Status()[0],"active_capsule")==a.old&&Text(a.l.Status()[0],"phase")=="active","qualified previous did not roll back");
        Check(UInt(a.l.Status()[0],"sequence")==2,"rollback reset sequence");
        auto gap=f.Import(f.Channel(4,a.old,a.old));Reject([&]{a.l.Stage(gap,f.now);},"SEC_CHANNEL_SEQUENCE_GAP_OR_ROLLBACK");
        auto backward=f.Import(f.Channel(1,a.old));Reject([&]{a.l.Stage(backward,f.now);},"SEC_CHANNEL_SEQUENCE_GAP_OR_ROLLBACK");
    });
    h.Test("renewed-signed-peer-lease-preserves-eligible-canary-compatibility-and-rearms-incident",[]{
        Active a(false,40000);auto& f=a.f;f.now=a.base+1001;std::vector<std::string> campaigns;
        for(const auto& gate:GATES){
            auto body=Common(f.realm,1,f.now);body.pushKV("composition",f.composition);body.pushKV("package",Hash("test package "+gate));body.pushKV("suite",Hash("suite "+gate));body.pushKV("sample_commitment",Hash("samples "+gate));body.pushKV("gate",gate);body.pushKV("interval_ms",30000);body.pushKV("max_rounds",2);
            auto campaign=f.Import(Signed("campaign",body,f.owner));campaigns.push_back(campaign);
            auto challenge_body=f.Challenge(f.composition,gate)["body"];challenge_body.pushKV("campaign",campaign);auto challenge=Signed("challenge",challenge_body,f.owner);f.Import(challenge);f.Import(f.Evaluation(challenge,f.alice,"host-a"));f.Import(f.Evaluation(challenge,f.bob,"host-b"));
        }
        auto settings=Object();settings.pushKV("enabled",true);settings.pushKV("max_evidence_age_ms",180000);settings.pushKV("allowed_campaigns",Strings(campaigns));f.local.pushKV("continuous_security",settings);f.SaveLocal();
        // Owner-enrolled, locally available isolated fixture; guards remain enabled.
        f.db.SetMeta("mesh_required","1");f.db.SetMeta("runtime_available","1");
        auto renew=[&]{auto b=Common(f.realm,1,f.now,30000);b.pushKV("sender",KeyId(f.bob.public_key));b.pushKV("recipient",KeyId(f.alice.public_key));b.pushKV("phase","request");b.pushKV("nonce",Hex(RandomBytes(32)));b.pushKV("cursor","");b.pushKV("want",Array());MeshHandle(f.db,Signed("mesh",b,f.bob),Hash("pin-b"),f.now);};
        renew();MeshRequireLive(f.db,f.policy,a.old,f.now);
        f.now=a.base+31002;Reject([&]{MeshRequireLive(f.db,f.policy,a.old,f.now);},"SEC_MESH_PEER_OFFLINE");a.l.Tick(f.now);Phase(f.db,"frozen","expired signed peer lease did not freeze");
        renew();MeshRequireLive(f.db,f.policy,a.old,f.now); // The old active is eligible again; preserve existing canary dispatch authority.
        auto cap=f.Capsule(f.composition,f.evaluations);a.Next(f.composition,cap);
        auto grant=f.db.Get(f.Grant(20))["body"];grant.pushKV("composition","");grant.pushKV("capsule","");grant.pushKV("channel","coding/stable");auto id=f.Import(Signed("grant",grant,f.owner));
        Broker broker(f.db,std::string(64,'c'));Check(broker.CanRelease(id,f.Context(),f.ReadRequest(),f.now),"eligible old-active canary compatibility changed");
        a.l.Tick(f.now);Check(a.l.Status()[0]["candidate_capsule"].get_str()==cap,"eligible restored active destroyed canary");
        f.Revoke(a.old);a.l.Tick(f.now);Phase(f.db,"frozen","fresh incident after eligibility recovery was suppressed");Check(a.l.Status()[0]["candidate_capsule"].get_str().empty(),"fresh same-generation incident retained candidate");
    });
    auto result=Object();result.pushKV("passed",static_cast<uint64_t>(h.passed));result.pushKV("failed",static_cast<uint64_t>(h.failed));result.pushKV("tests",h.results);
    if(argc>1){EnsurePrivateDirectory(fs::path(argv[1]).parent_path());WritePrivate(argv[1],Canonical(result),true);std::string journal;for(const auto& record:signed_records.getValues())journal+=Canonical(record)+"\n";WritePrivate(std::string(argv[1])+".records.jsonl",journal,true);}std::cout<<Canonical(result)<<'\n';return h.failed?1:0;
}

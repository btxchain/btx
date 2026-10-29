// Copyright (c) 2026 The BTX developers. MIT license.
// All identities, credentials and model tensors below are synthetic fixtures.
// Two signer identities on this test host do NOT qualify two physical hosts.
#include <modelnet/security_v2/service.h>
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
struct Fixture {
    Temp temp;fs::path root;Database db;
    KeyPair owner=GenerateKey(),publisher=GenerateKey(),second=GenerateKey(),alice=GenerateKey(),bob=GenerateKey();
    std::string realm=Hash("test realm"),session=Hex(RandomBytes(32)),runtime=Hash("test runtime"),schema=Hash("tool schema");
    int64_t now=NowMs();Json policy_record,local;
    Policy policy;
    fs::path probe;
    std::string capsule,composition;std::vector<std::string> evaluations;
    explicit Fixture(fs::path executable={},bool common_domain=false):root(temp.root/"security"),db(root),probe(std::move(executable)) {
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
        b.pushKV("principals",principals);policy_record=Signed("policy",b,owner);InstallPolicy(db,policy_record,now);policy=Policy::Load(db,now);
        EnsurePrivateDirectory(temp.root/"workspace");WritePrivate(temp.root/"workspace"/"source.txt","hello safe workspace\n");
        WritePrivate(temp.root/"workspace"/".env","SYNTHETIC_DECOY=not-a-real-secret\n");
        local=Object();local.pushKV("schema","BTX/SecurityLocal/v1");local.pushKV("host","host-a");auto work=Object();work.pushKV("code",(temp.root/"workspace").string());local.pushKV("workspaces",work);
        local.pushKV("packages",Object());local.pushKV("evaluation_plans",Object());local.pushKV("runtimes",Object());
        auto identity=Object();identity.pushKV("public_key",Hex(alice.public_key));identity.pushKV("secret_file",(root/"worker.key").string());local.pushKV("identity",identity);WritePrivate(root/"worker.key",Hex(alice.secret_key));
        auto compute=Object();compute.pushKV("allow_evaluation",true);compute.pushKV("max_memory_bytes",512*1024*1024);compute.pushKV("max_wall_ms",5000);compute.pushKV("max_cpu_ms",4000);local.pushKV("execution_policy",compute);SaveLocal();
        composition=MakeComposition("base");capsule=MakeEvidence(composition);
    }
    void SaveLocal(){WritePrivate(root/"local.json",Canonical(local),true);}
    std::string Import(const Json& e){ImportRecord(db,policy,e,NowMs());return RecordId(e);}
    Json Context(const std::string& c={}) {auto x=Object();x.pushKV("realm",realm);x.pushKV("composition",c.empty()?composition:c);x.pushKV("runtime",runtime);x.pushKV("tool_schema",schema);x.pushKV("session",session);return x;}
    std::string MakeComposition(const std::string& version,const std::vector<std::string>& parents={}) {
        auto b=Object();b.pushKV("realm",realm);b.pushKV("policy_epoch",1);b.pushKV("runtime",runtime);b.pushKV("sandbox",StaticSandboxDigest());b.pushKV("tool_schema",schema);b.pushKV("system_prompt",Hash("fixed system prompt"));b.pushKV("parents",Strings(parents));b.pushKV("contributors",Strings({KeyId(publisher.public_key)}));b.pushKV("license","MIT-test-fixture");b.pushKV("architecture","synthetic-fixture-not-an-LLM");b.pushKV("visibility","public");
        auto files=Array();const auto source=temp.root/("source-"+version);EnsurePrivateDirectory(source);
        const std::vector<std::pair<std::string,std::string>> components{{"weights.safetensors","weights"},{"tokenizer.json","tokenizer"},{"config.json","config"},{"chat.txt","chat_template"}};
        for(const auto& [path,role]:components) {
            std::string bytes=role=="weights"?std::string("synthetic tensors ")+version:std::string("{} ")+version;
            WritePrivate(source/path,bytes);auto f=Object();f.pushKV("path",path);f.pushKV("role",role);f.pushKV("sha384",Hash(bytes));f.pushKV("bytes",static_cast<uint64_t>(bytes.size()));files.push_back(f);
        }
        b.pushKV("files",files);auto e=Signed("composition",b,publisher);auto id=Import(e);ImportResident(db,policy,id,source,1024*1024,NowMs());return id;
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
    std::string Capsule(const std::string& c,const std::vector<std::string>& reports) {
        auto b=Common(realm,1,now);b.pushKV("composition",c);b.pushKV("evaluations",Strings(reports));b.pushKV("profile","restricted-tools");return Import(Signed("capsule",b,owner,&second));
    }
    std::string MakeEvidence(const std::string& c) {
        std::vector<std::string> reports;
        for(const auto& gate:GATES){auto ch=Challenge(c,gate);Import(ch);reports.push_back(Import(Evaluation(ch,alice,"host-a")));reports.push_back(Import(Evaluation(ch,bob,"host-b")));}
        evaluations=reports;return Capsule(c,reports);
    }
    std::string Grant(unsigned calls=4) {
        auto b=Common(realm,1,now);b.pushKV("composition",composition);b.pushKV("channel","");b.pushKV("capsule",capsule);b.pushKV("runtime",runtime);b.pushKV("tool_schema",schema);b.pushKV("session",session);b.pushKV("workspace","code");b.pushKV("tools",Strings({"read","hash","write-new","run-static"}));b.pushKV("read_paths",Strings({"source.txt","link.txt"}));b.pushKV("write_paths",Strings({"new.txt"}));std::vector<std::string> packages;for(const auto& x:local["packages"].getKeys())packages.push_back(x);b.pushKV("packages",Strings(packages));b.pushKV("max_calls",calls);b.pushKV("max_bytes",262144);b.pushKV("per_action_bytes",65536);return Import(Signed("grant",b,owner));
    }
    void Revoke(const std::string& id){auto b=Common(realm,1,NowMs());b.pushKV("subject",id);b.pushKV("sequence",1);b.pushKV("reason","test incident");auto e=Signed("revocation",b,owner,&second);ImportRecord(db,Policy::Load(db,NowMs()),e,NowMs());}
    Json ReadRequest(){auto r=Object();r.pushKV("tool","read");r.pushKV("path","source.txt");return r;}
    std::string InstallProbePackage(){auto p=Object();p.pushKV("executable",probe.string());p.pushKV("sha384",Hash(ReadFile(probe,128*1024*1024)));p.pushKV("sandbox",StaticSandboxDigest());p.pushKV("wall_ms",1000);p.pushKV("cpu_ms",1000);p.pushKV("memory_bytes",256*1024*1024);const auto id=DomainHash("BTX/LocalStaticPackage/v1",Canonical(p));auto packages=local["packages"];packages.pushKV(id,p);local.pushKV("packages",packages);SaveLocal();return id;}
    Json FollowMandate(std::string runtime_id={}){auto b=Common(realm,1,now);b.pushKV("channel","coding/stable");b.pushKV("profile","restricted-tools");b.pushKV("runtimes",Strings({runtime_id.empty()?runtime:runtime_id}));b.pushKV("tool_schemas",Strings({schema}));b.pushKV("automatic_follow",true);return Signed("mandate",b,owner);}
    Json Channel(unsigned seq,const std::string& cap,std::string previous=""){auto b=Common(realm,1,now);b.pushKV("name","coding/stable");b.pushKV("sequence",seq);b.pushKV("capsule",cap);b.pushKV("previous",previous);return Signed("channel",b,owner,&second);}
};
std::string ExpectedProbe(){return "{\"filesystem_denied\":true,\"network_denied\":true,\"fork_denied\":true,\"environment_clean\":true}\n";}
std::string InstallPlan(Fixture& f,const std::string& gate="adversarial") {
    auto plan=Object();plan.pushKV("schema","BTX/StaticEvaluationPlan/v1");plan.pushKV("suite",Hash("suite "+gate));plan.pushKV("sample_commitment",Hash("samples "+gate));plan.pushKV("gate",gate);plan.pushKV("executable_sha384",Hash(ReadFile(f.probe,128*1024*1024)));plan.pushKV("sandbox",StaticSandboxDigest());plan.pushKV("input_sha384",Hash("probe"));plan.pushKV("expected_output_sha384",Hash(ExpectedProbe()));plan.pushKV("expected_output_bytes",static_cast<uint64_t>(ExpectedProbe().size()));plan.pushKV("cases",1);plan.pushKV("memory_bytes",256*1024*1024);plan.pushKV("wall_ms",2000);plan.pushKV("cpu_ms",1000);plan.pushKV("output_bytes",65536);
    const auto id=PlanId(plan);WritePrivate(f.root/"probe-input","probe",true);auto entry=Object();entry.pushKV("plan",plan);entry.pushKV("executable",f.probe.string());entry.pushKV("input_file",(f.root/"probe-input").string());auto plans=f.local["evaluation_plans"];plans.pushKV(id,entry);f.local.pushKV("evaluation_plans",plans);auto runtime=Object();runtime.pushKV("canary_package",id);auto runtimes=f.local["runtimes"];runtimes.pushKV(f.runtime,runtime);f.local.pushKV("runtimes",runtimes);f.SaveLocal();return id;
}
Json Control(Fixture& f){auto b=Common(f.realm,1,NowMs());b.pushKV("operation","resume");b.pushKV("nonce",Hex(RandomBytes(32)));return Signed("control",b,f.owner);}
// The coordinator (f.db) runs a 2 s campaign. Evaluator bob then syncs from it
// while advertised records cannot be imported on bob's node:
// - "expired-record": bob joins after round 0 expired;
// - "revoked-record": bob already holds a revocation of round 0;
// - "revoked-signer": bob already holds a revocation of the publisher key, so
//   the composition is refused;
// - "old-epoch-records": records from before a policy epoch bump;
// - "many-expired-records": bob joins after 120 rounds expired, and must still
//   get 8 compositions exported after them and stop wanting the expired ones.
// Returns an empty string when bob still receives the new records.
std::string LateEvaluatorMissesNewRecords(Fixture& f,const std::string& mode) {
    std::vector<std::string> live;
    if(mode=="many-expired-records")for(int k=0;k<8;++k)live.push_back(f.MakeComposition("live"+std::to_string(k)));
    const int64_t t0=NowMs()+1000;
    auto cb=Common(f.realm,1,t0,300000);cb.pushKV("composition",f.composition);cb.pushKV("package",Hash("late package"));cb.pushKV("suite",Hash("suite adversarial"));cb.pushKV("sample_commitment",Hash("samples adversarial"));cb.pushKV("gate","adversarial");cb.pushKV("interval_ms",static_cast<uint64_t>(2000));cb.pushKV("max_rounds",static_cast<uint64_t>(1000));
    const auto campaign_record=Signed("campaign",cb,f.owner);ImportRecord(f.db,f.policy,campaign_record,t0);const auto campaign=RecordId(campaign_record);MeshExport(f.db,campaign,t0);
    auto worker=f.local;auto settings=Object();settings.pushKV("enabled",true);settings.pushKV("max_evidence_age_ms",static_cast<uint64_t>(180000));settings.pushKV("allowed_campaigns",Strings({campaign}));
    auto owner_id=Object();owner_id.pushKV("public_key",Hex(f.owner.public_key));owner_id.pushKV("secret_file",(f.root/"coordinator.key").string());WritePrivate(f.root/"coordinator.key",Hex(f.owner.secret_key));
    f.local.pushKV("host","owner-host");f.local.pushKV("identity",owner_id);f.local.pushKV("continuous_security",settings);f.SaveLocal();
    MeshTick(f.db,t0);
    auto round=[&](uint64_t n){auto r=f.db.Query("SELECT challenge FROM mesh_rounds WHERE campaign=? AND round=?",{campaign,std::to_string(n)});Check(r.size()==1,"round not scheduled");return r[0][0];};
    const auto first=round(0);
    for(int k=1;k<120&&!live.empty();++k)MeshTick(f.db,t0+2000*k);
    Json epoch2;
    if(mode=="old-epoch-records"){auto b=f.policy_record["body"];b.pushKV("epoch",2);b.pushKV("issued_ms",t0+300);b.pushKV("expires_ms",t0+3600000);epoch2=Signed("policy",b,f.owner);InstallPolicy(f.db,epoch2,t0+300);}
    const int64_t join=mode=="expired-record"?t0+5000:live.empty()?t0+500:t0+245000;
    const auto path=f.temp.root/"late-evaluator";EnsurePrivateDirectory(path);WritePrivate(path/"root-pins.json",ReadFile(f.root/"root-pins.json"));
    Database late(path);InstallPolicy(late,f.policy_record,join-100);if(epoch2.isObject())InstallPolicy(late,epoch2,join-100);
    auto identity=Object();identity.pushKV("public_key",Hex(f.bob.public_key));identity.pushKV("secret_file",(path/"identity.key").string());WritePrivate(path/"identity.key",Hex(f.bob.secret_key));
    worker.pushKV("host","host-b");worker.pushKV("identity",identity);worker.pushKV("continuous_security",settings);WritePrivate(path/"local.json",Canonical(worker));
    const auto blocked=mode=="revoked-signer"?f.composition:first;
    if(mode=="revoked-record"||mode=="revoked-signer"){auto b=Common(f.realm,1,join-50);b.pushKV("subject",mode=="revoked-signer"?KeyId(f.publisher.public_key):first);b.pushKV("sequence",1);b.pushKV("reason","test incident");ImportRecord(late,Policy::Load(late,join-50),Signed("revocation",b,f.owner,&f.second),join-50);}
    const auto coordinator=KeyId(f.owner.public_key);std::string error;
    auto sync=[&](int64_t t){auto reply=MeshHandle(f.db,MeshRequest(late,coordinator,t),Hash("pin-b"),t);try{MeshAccept(late,reply,Hash("pin-owner"),t);}catch(const Error& e){error=e.code;}};
    for(const auto& c:live)MeshExport(f.db,c,join-50);
    sync(join);sync(join+100);
    if(!live.empty()){
        for(int k=1;k<=40;++k)sync(join+1100*k);
        size_t held=0;for(const auto& c:live)held+=late.Has(c);
        Check(!late.Has(blocked),"unimportable record stored");
        const auto wants=late.Query("SELECT count(*) FROM mesh_wants")[0][0]; // refused ids must not be wanted again
        return held==live.size()&&wants=="0"?std::string():"received "+std::to_string(held)+" of 8 new records, "+wants+" wants left; last MeshAccept error "+error;
    }
    MeshTick(f.db,t0+6000);const auto later=round(3);
    for(int64_t t:{6100,6200,6300})sync(t0+t);
    Check(!late.Has(blocked),"unimportable record stored");
    return late.Has(later)?std::string():"later round not received; last MeshAccept error "+error;
}
}
int main(int argc,char** argv) {
    fs::path probe;fs::path report;
    if(argc>1)probe=fs::absolute(argv[1]);if(argc>2)report=fs::absolute(argv[2]);
    Harness h;
    h.Test("canonical-key-order",[]{Check(Canonical(Parse("{\"b\":2,\"a\":1}"))=="{\"a\":1,\"b\":2}","order");});
    h.Test("duplicate-json-keys-rejected",[]{Reject([]{Parse("{\"a\":1,\"a\":2}");},"SEC_JSON_DUPLICATE");});
    h.Test("float-json-rejected",[]{Reject([]{Parse("{\"a\":1.25}");});});
    h.Test("negative-zero-rejected",[]{Reject([]{Parse("{\"a\":-0}");});});
    h.Test("record-size-bounded",[]{Reject([]{Parse(std::string(MAX_RECORD+1,'x'));});});
    h.Test("mldsa-real-roundtrip-and-domain-separation",[]{auto k=GenerateKey();auto b=Object();b.pushKV("data",1);auto s=Unhex(Sign("receipt",b,k.secret_key));Check(Verify("receipt",b,k.public_key,s),"signature");Check(!Verify("grant",b,k.public_key,s),"domain");b.pushKV("data",2);Check(!Verify("receipt",b,k.public_key,s),"tamper");});
    h.Test("path-traversal-and-dos-names-rejected",[]{for(auto x:{"../outside","/root/a","a/../b","a\\b","CON","x/.ssh/id_rsa",".env.production"})Check(!IsPortablePath(x)||IsCredentialPath(x),"path accepted");});
    h.Test("policy-real-pq-pins-and-admission",[&]{Fixture f;auto a=AdmitCapsule(f.db,f.policy,f.capsule,f.now);Check(a.domains.size()==2&&a.hosts.size()==2,"coverage");Check(f.db.VerifyJournal(),"journal");});
    h.Test("one-domain-sybil-identities-insufficient",[&]{Fixture f({},true);Reject([&]{AdmitCapsule(f.db,f.policy,f.capsule,f.now);},"SEC_INDEPENDENT_COVERAGE");});
    h.Test("missing-gate-blocks-admission",[&]{Fixture f;auto refs=f.evaluations;refs.resize(10);auto id=f.Capsule(f.composition,refs);Reject([&]{AdmitCapsule(f.db,f.policy,id,f.now);},"SEC_INDEPENDENT_COVERAGE");});
    h.Test("unreferenced-negative-result-blocks-admission",[&]{Fixture f;auto ch=f.Challenge(f.composition,"adversarial");f.Import(f.Evaluation(ch,f.alice,"host-a","FAIL"));Reject([&]{AdmitCapsule(f.db,f.policy,f.capsule,f.now);},"SEC_NEGATIVE_EVIDENCE");});
    h.Test("dangling-execution-receipt-cannot-pass",[&]{Fixture f;auto e=f.db.Get(f.evaluations[0]);auto body=e["body"];body.pushKV("execution_receipt",Hash("absent receipt"));auto replacement=f.Import(Signed("evaluation",body,f.alice));auto refs=f.evaluations;refs[0]=replacement;auto cap=f.Capsule(f.composition,refs);Reject([&]{AdmitCapsule(f.db,f.policy,cap,f.now);},"SEC_OBJECT_ABSENT");});
    h.Test("modified-evaluation-signature-refused",[&]{Fixture f;auto e=f.db.Get(f.evaluations[0]);auto b=e["body"];b.pushKV("cases",999);e.pushKV("body",b);Reject([&]{f.Import(e);},"SEC_SIGNATURE");});
    h.Test("wrong-release-threshold-refused",[&]{Fixture f;auto e=f.db.Get(f.capsule);auto one=Envelope("capsule",e["body"]);AddSignature(one,f.owner);auto b=one["body"];b.pushKV("expires_ms",f.now+59000);one=Signed("capsule",b,f.owner);Reject([&]{f.Import(one);},"SEC_SIGNATURE_THRESHOLD");});
    h.Test("expiry-rechecked-at-admission",[&]{Fixture f;Reject([&]{AdmitCapsule(f.db,f.policy,f.capsule,f.now+60000);});});
    h.Test("publisher-revocation-quarantines-artifact",[&]{Fixture f;f.Revoke(KeyId(f.publisher.public_key));Reject([&]{AdmitCapsule(f.db,Policy::Load(f.db,NowMs()),f.capsule,NowMs());});});
    h.Test("revocation-inherited-through-lineage",[&]{Fixture f;auto child=f.MakeComposition("child",{f.composition});f.Revoke(f.composition);Check(f.db.AncestryRevoked(child,NowMs()),"lineage not quarantined");});
    h.Test("same-bytes-wrong-context-denied",[&]{Fixture f;auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto c=f.Context();c.pushKV("runtime",Hash("substitute"));Reject([&]{b.Prepare(g,c,f.ReadRequest(),NowMs());},"SEC_CONTEXT_BINDING");});
    h.Test("credential-resource-denied-before-permit",[&]{Fixture f;auto g=f.Grant();auto r=f.ReadRequest();r.pushKV("path",".env");Reject([&]{Broker(f.db,Hex(RandomBytes(32))).Prepare(g,f.Context(),r,NowMs());},"SEC_PROTECTED_RESOURCE");});
    h.Test("arbitrary-shell-and-network-tools-denied",[&]{for(auto tool:{"exec_command","shell","curl","network","download-and-execute"}){auto r=Object();r.pushKV("tool",tool);Reject([&]{RequestDigest(r);},"SEC_TOOL_DENIED");}});
    h.Test("read-effect-actually-dispatched",[&]{Fixture f;auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto p=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());auto r=b.Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());Check(Boolean(r,"ok")&&Boolean(r,"dispatched"),"effect not dispatched");auto bytes=Unhex(Text(r,"output_hex"));Check(std::string(bytes.begin(),bytes.end())=="hello safe workspace\n","read output");auto stored=b.Result(Text(p,"permit"));Check(!stored["result"].exists("output_hex"),"private output persisted");});
    h.Test("single-use-replay-refused",[&]{Fixture f;auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto p=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());b.Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());Reject([&]{b.Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());},"SEC_PERMIT_REPLAY");});
    h.Test("argument-substitution-refused",[&]{Fixture f;auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto p=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());auto changed=f.ReadRequest();changed.pushKV("path","link.txt");Reject([&]{b.Execute(Text(p,"secret"),f.Context(),changed,NowMs());},"SEC_ARGUMENT_SUBSTITUTION");});
    h.Test("restart-invalidates-bearer",[&]{Fixture f;auto g=f.Grant();auto p=Broker(f.db,Hex(RandomBytes(32))).Prepare(g,f.Context(),f.ReadRequest(),NowMs());Reject([&]{Broker(f.db,Hex(RandomBytes(32))).Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());},"SEC_PERMIT_EXPIRED_OR_RESTARTED");});
    h.Test("persistent-budget-cannot-reset-permit",[&]{Fixture f;auto g=f.Grant(1);Broker b(f.db,Hex(RandomBytes(32)));auto a=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());auto c=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());b.Execute(Text(a,"secret"),f.Context(),f.ReadRequest(),NowMs());Reject([&]{b.Execute(Text(c,"secret"),f.Context(),f.ReadRequest(),NowMs());},"SEC_BUDGET_EXHAUSTED");});
    h.Test("pause-resume-does-not-resurrect-permit",[&]{Fixture f;auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto p=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());b.Pause(NowMs());auto control=Control(f);b.Resume(control,NowMs());Reject([&]{b.Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());},"SEC_PERMIT_REPLAY");b.Pause(NowMs());Reject([&]{b.Resume(control,NowMs());},"SEC_RESUME_REPLAY");});
    h.Test("broker-accepts-documented-remote-work-config",[&]{Fixture f;auto rw=Object();rw.pushKV("enabled",true);rw.pushKV("packages",Strings({Hash("owner-installed static plan")}));rw.pushKV("compositions",Strings({f.composition}));f.local.pushKV("remote_work",rw);f.SaveLocal();auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto p=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());auto r=b.Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());Check(Boolean(r,"ok")&&Boolean(r,"dispatched"),r.write().c_str());});
    h.Test("revocation-after-prepare-blocks-effect",[&]{Fixture f;auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto p=b.Prepare(g,f.Context(),f.ReadRequest(),NowMs());f.Revoke(g);Reject([&]{b.Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());});});
#ifndef _WIN32
    h.Test("symlink-read-escape-refused",[&]{Fixture f;fs::create_symlink(f.temp.root/"workspace"/".env",f.temp.root/"workspace"/"link.txt");auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto r=f.ReadRequest();r.pushKV("path","link.txt");auto p=b.Prepare(g,f.Context(),r,NowMs());auto result=b.Execute(Text(p,"secret"),f.Context(),r,NowMs());Check(!Boolean(result,"ok"),"symlink escaped");});
    h.Test("hardlink-read-escape-refused",[&]{Fixture f;fs::create_hard_link(f.temp.root/"workspace"/".env",f.temp.root/"workspace"/"link.txt");auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto r=f.ReadRequest();r.pushKV("path","link.txt");auto p=b.Prepare(g,f.Context(),r,NowMs());auto result=b.Execute(Text(p,"secret"),f.Context(),r,NowMs());Check(!Boolean(result,"ok"),"hardlink escaped");});
#endif
    h.Test("write-new-effect-and-overwrite-denial",[&]{Fixture f;auto g=f.Grant();Broker b(f.db,Hex(RandomBytes(32)));auto r=Object();r.pushKV("tool","write-new");r.pushKV("path","new.txt");r.pushKV("payload_hex","616263");auto p=b.Prepare(g,f.Context(),r,NowMs());Check(Boolean(b.Execute(Text(p,"secret"),f.Context(),r,NowMs()),"ok"),"write failed");Check(ReadFile(f.temp.root/"workspace"/"new.txt")=="abc","write bytes");p=b.Prepare(g,f.Context(),r,NowMs());Check(!Boolean(b.Execute(Text(p,"secret"),f.Context(),r,NowMs()),"ok"),"overwrite accepted");});
    h.Test("concurrent-replay-has-one-winner",[&]{Fixture f;auto g=f.Grant();const auto boot=Hex(RandomBytes(32));auto p=Broker(f.db,boot).Prepare(g,f.Context(),f.ReadRequest(),NowMs());std::atomic<int> successes{0};auto work=[&]{try{Database db(f.root);auto r=Broker(db,boot).Execute(Text(p,"secret"),f.Context(),f.ReadRequest(),NowMs());if(Boolean(r,"ok"))++successes;}catch(const Error&){};};std::thread one(work),two(work);one.join();two.join();Check(successes==1,"not exactly one dispatch");});
    h.Test("clock-rollback-refused",[&]{Fixture f;Database::Transaction tx(f.db);auto time=NowMs()+100;f.db.CheckClock(time);Reject([&]{f.db.CheckClock(time-1);},"SEC_CLOCK_ROLLBACK");});
    h.Test("resident-tamper-detected",[&]{Fixture f;auto path=f.root/"artifacts"/f.composition/"config.json";WritePrivate(path,"tampered",true);Reject([&]{VerifyResident(f.db,f.composition);});});
    h.Test("resident-extra-file-detected",[&]{Fixture f;WritePrivate(f.root/"artifacts"/f.composition/"unlisted.py","not executed");Reject([&]{VerifyResident(f.db,f.composition);},"SEC_RESIDENT_EXTRA_FILE");});
    h.Test("journal-tampering-detected",[&]{Fixture f;f.db.Exec("UPDATE events SET digest=? WHERE seq=1",{Hash("fake")});Check(!f.db.VerifyJournal(),"journal accepted corruption");});
    h.Test("stage-needs-owner-follow-and-resident-bytes",[&]{Fixture f;auto update=f.Import(f.Channel(1,f.capsule));Reject([&]{Lifecycle(f.db).Stage(update,NowMs());},"SEC_CHANNEL_NOT_FOLLOWED");auto m=f.Import(f.FollowMandate());Lifecycle(f.db).Follow(m,NowMs());Lifecycle(f.db).Stage(update,NowMs());Check(Text(Lifecycle(f.db).Status()[0],"phase")=="canary","not staged");Reject([&]{Lifecycle(f.db).Activate("coding/stable",NowMs());},"SEC_CANARY_DURATION");});
    h.Test("update-cannot-expand-runtime-authority",[&]{Fixture f;auto m=f.Import(f.FollowMandate(Hash("other runtime")));Lifecycle(f.db).Follow(m,NowMs());auto update=f.Import(f.Channel(1,f.capsule));Reject([&]{Lifecycle(f.db).Stage(update,NowMs());},"SEC_UPDATE_AUTHORITY_EXPANSION");});
    h.Test("signed-channel-equivocation-freezes-host",[&]{Fixture f;auto m=f.Import(f.FollowMandate());Lifecycle l(f.db);l.Follow(m,NowMs());auto a=f.Channel(1,f.capsule);l.Stage(f.Import(a),NowMs());auto b=a["body"];b.pushKV("expires_ms",f.now+59000);auto other=f.Import(Signed("channel",b,f.owner,&f.second));Reject([&]{l.Stage(other,NowMs());},"SEC_CHANNEL_EQUIVOCATION");Check(Text(l.Status()[0],"phase")=="frozen","not frozen");});
    h.Test("peer-cannot-import-local-grant",[&]{Fixture f;auto grant=f.db.Get(f.Grant());Reject([&]{ImportRecord(f.db,f.policy,grant,NowMs(),true);},"SEC_PEER_CANNOT_GRANT");});
    h.Test("public-evidence-closure-excludes-grants",[&]{Fixture f;PublishEvidenceClosure(f.db,f.capsule,NowMs());Check(!f.db.Query("SELECT id FROM objects WHERE id=? AND visibility='public'",{f.capsule}).empty(),"capsule unpublished");auto grant=f.Grant();Reject([&]{PublishEvidenceClosure(f.db,grant,NowMs());},"SEC_PRIVATE_KIND");});
    h.Test("peer-authenticated-inventory-and-replay-rejection",[&]{Fixture f;PublishEvidenceClosure(f.db,f.capsule,NowMs());auto b=Common(f.realm,1,NowMs(),30000);b.pushKV("sender",KeyId(f.bob.public_key));b.pushKV("recipient",KeyId(f.alice.public_key));b.pushKV("phase","request");b.pushKV("nonce",Hex(RandomBytes(32)));b.pushKV("cursor","");b.pushKV("want",Strings({f.capsule}));auto request=Signed("peer",b,f.bob);Reject([&]{HandlePeerRequest(f.db,request,Hash("wrong-pin"),NowMs());},"SEC_PEER_TRANSPORT_PIN");auto response=HandlePeerRequest(f.db,request,Hash("pin-b"),NowMs());Check(response["body"]["records"].size()==1,"record missing");Reject([&]{HandlePeerRequest(f.db,request,Hash("pin-b"),NowMs());},"SEC_PEER_REPLAY");});
    h.Test("private-object-and-missing-object-indistinguishable",[&]{Fixture f;auto grant=f.Grant();auto b=Common(f.realm,1,NowMs(),30000);b.pushKV("sender",KeyId(f.bob.public_key));b.pushKV("recipient",KeyId(f.alice.public_key));b.pushKV("phase","request");b.pushKV("nonce",Hex(RandomBytes(32)));b.pushKV("cursor","");b.pushKV("want",Strings({grant,Hash("absent")}));auto response=HandlePeerRequest(f.db,Signed("peer",b,f.bob),Hash("pin-b"),NowMs());Check(response["body"]["records"].size()==0&&response["body"]["not_available"].size()==2,"private oracle");});
#if defined(__linux__)
    h.Test("native-sandbox-denies-file-network-fork-and-env",[&]{Check(!probe.empty(),"probe path required");setenv("BTX_SECRET_SENTINEL","SYNTHETIC_NOT_A_CREDENTIAL",1);auto bytes=ReadFile(probe,128*1024*1024);auto r=RunStaticWorker(probe,Hash(bytes),"probe",SandboxLimits{},[]{return true;});unsetenv("BTX_SECRET_SENTINEL");Check(r.dispatched&&r.enforced&&r.error.empty()&&r.exit_code==0&&r.output==ExpectedProbe(),r.error.c_str());});
    h.Test("native-sandbox-executable-substitution-refused",[&]{Reject([&]{RunStaticWorker(probe,Hash("wrong"),"",SandboxLimits{},[]{return true;});},"SEC_EXECUTABLE_DIGEST");});
    h.Test("native-sandbox-timeout-kills-owned-child",[&]{auto limits=SandboxLimits{};limits.wall_ms=100;limits.cpu_ms=100;auto r=RunStaticWorker(probe,Hash(ReadFile(probe,128*1024*1024)),"sleep",limits,[]{return true;});Check(r.timed_out&&!r.error.empty()&&r.output.empty(),"timeout missing");});
    h.Test("native-sandbox-output-cap",[&]{auto limits=SandboxLimits{};limits.output_bytes=128;auto r=RunStaticWorker(probe,Hash(ReadFile(probe,128*1024*1024)),"flood",limits,[]{return true;});Check(r.error=="SEC_OUTPUT_LIMIT"&&r.output.empty(),"output escaped");});
    h.Test("native-sandbox-revocation-cancels-and-withholds",[&]{std::atomic<int> count{0};auto r=RunStaticWorker(probe,Hash(ReadFile(probe,128*1024*1024)),"sleep",SandboxLimits{},[&]{return ++count<4;});Check(r.cancelled&&!r.error.empty()&&r.output.empty(),"cancel missing");});
    h.Test("signed-action-actually-executes-confined-worker",[&]{Fixture f(probe);auto package=f.InstallProbePackage();auto g=f.Grant();auto request=Object();request.pushKV("tool","run-static");request.pushKV("package",package);request.pushKV("payload_hex","70726f6265");Broker b(f.db,Hex(RandomBytes(32)));auto p=b.Prepare(g,f.Context(),request,NowMs());auto r=b.Execute(Text(p,"secret"),f.Context(),request,NowMs());Check(Boolean(r,"ok")&&Boolean(r,"sandbox_enforced")&&Boolean(r,"dispatched"),r.write().c_str());});
    h.Test("real-evaluation-produces-bound-signed-receipt",[&]{Fixture f(probe);auto package=InstallPlan(f);auto challenge=f.Challenge(f.composition,"adversarial",package);auto id=f.Import(challenge);auto report=EvaluateChallenge(f.db,id,NowMs());Check(Text(report["body"],"outcome")=="PASS","probe evaluation failed");auto receipt=f.db.Get(Text(report["body"],"execution_receipt"));Check(Boolean(receipt["body"],"dispatched"),"not dispatched");Check(Text(receipt["body"],"request")==id,"request binding");Reject([&]{EvaluateChallenge(f.db,id,NowMs());},"SEC_EVALUATION_ALREADY_ATTEMPTED");});
    h.Test("real-canaries-activate-persistent-model-binding",[&]{Fixture f(probe);InstallPlan(f);Lifecycle l(f.db);auto mandate=f.Import(f.FollowMandate());l.Follow(mandate,NowMs());auto update=f.Import(f.Channel(1,f.capsule));l.Stage(update,NowMs());auto first=RunChannelCanary(f.db,"coding/stable",NowMs());l.Observe("coding/stable",RecordId(first),NowMs());std::this_thread::sleep_for(std::chrono::milliseconds(1050));auto second=RunChannelCanary(f.db,"coding/stable",NowMs());l.Observe("coding/stable",RecordId(second),NowMs());l.Activate("coding/stable",NowMs());Check(Text(l.Status()[0],"phase")=="active","not activated");Check(Text(l.Status()[0],"active_capsule")==f.capsule,"wrong active");f.Revoke(f.composition);l.Tick(NowMs());Check(Text(l.Status()[0],"phase")=="frozen","incident did not freeze");});
#endif
    h.Test("mesh-cross-database-signed-PQ-evidence-sync",[&]{
        Fixture f;
        MeshExport(f.db,f.capsule,NowMs());
        auto directory=f.temp.root/"other-host-security";
        EnsurePrivateDirectory(directory);
        WritePrivate(directory/"root-pins.json",ReadFile(f.root/"root-pins.json"));
        Database remote(directory);
        InstallPolicy(remote,f.policy_record,NowMs());
        auto settings=f.local;
        settings.pushKV("host","host-b");
        auto peerid=Object();peerid.pushKV("public_key",Hex(f.bob.public_key));
        peerid.pushKV("secret_file",(directory/"peer.key").string());
        WritePrivate(directory/"peer.key",Hex(f.bob.secret_key));
        settings.pushKV("identity",peerid);
        WritePrivate(directory/"local.json",Canonical(settings));
        const auto id=KeyId(f.alice.public_key);
        for(int j=0;j<24;++j){
            auto request=MeshRequest(remote,id,NowMs());
            auto reply=MeshHandle(f.db,request,Hash("pin-b"),NowMs());
            MeshAccept(remote,reply,Hash("pin-a"),NowMs());
            if(remote.Has(f.capsule)){
                try {(void)AdmitCapsule(remote,Policy::Load(remote,NowMs()),f.capsule,NowMs());break;}
                catch(const Error&){}
            }
        }
        auto admission=AdmitCapsule(remote,Policy::Load(remote,NowMs()),f.capsule,NowMs());
        Check(admission.domains.size()==2,"remote missing independent evidence closure");
        Check(MeshStatus(remote,NowMs())["authenticated_recent_peer_sessions"].getInt<uint64_t>()>=1,"no live signed session");
        auto req=MeshRequest(remote,id,NowMs());
        Reject([&]{MeshHandle(f.db,req,Hash("pin-a"),NowMs());},"SEC_MESH_PIN");
        auto reply=MeshHandle(f.db,req,Hash("pin-b"),NowMs());
        Reject([&]{MeshHandle(f.db,req,Hash("pin-b"),NowMs());},"SEC_MESH_REPLAY");
        MeshAccept(remote,reply,Hash("pin-a"),NowMs());
        Reject([&]{MeshAccept(remote,reply,Hash("pin-a"),NowMs());},"SEC_MESH_REPLAY");
    });
    for(const std::string mode:{"expired-record","revoked-record","revoked-signer","old-epoch-records","many-expired-records"})h.Test("mesh-sync-continues-past-"+mode,[&]{Fixture f;const auto r=LateEvaluatorMissesNewRecords(f,mode);Check(r.empty(),r.c_str());});
    // Fixture evaluations name campaign Hash("campaign "+gate); allowing those
    // makes MeshTick walk them. This node is host-a (alice).
    auto mesh_on=[](Fixture& f,bool fixture_campaigns){std::vector<std::string> c;if(fixture_campaigns)for(const auto& g:GATES)c.push_back(Hash("campaign "+g));auto s=Object();s.pushKV("enabled",true);s.pushKV("max_evidence_age_ms",static_cast<uint64_t>(60000));s.pushKV("allowed_campaigns",Strings(c));f.local.pushKV("continuous_security",s);f.SaveLocal();};
    h.Test("mesh-tick-skips-revoked-evaluator",[&]{Fixture f;mesh_on(f,true);MeshTick(f.db,NowMs());f.Revoke(KeyId(f.bob.public_key));f.db.Exec("DELETE FROM mesh_outbox");MeshTick(f.db,NowMs());Check(f.db.Query("SELECT count(*) FROM mesh_outbox WHERE kind='evaluation'")[0][0]=="6","local evaluations not exported");});
    h.Test("mesh-tick-skips-evaluator-dropped-by-new-policy",[&]{Fixture f;mesh_on(f,true);MeshTick(f.db,NowMs());auto carol=GenerateKey();auto b=f.policy_record["body"];Json principals=Array();for(auto row:b["principals"].getValues()){if(Text(row,"public_key",PK_BYTES*2)==Hex(f.bob.public_key))row.pushKV("public_key",Hex(carol.public_key));principals.push_back(row);}const auto now=NowMs();b.pushKV("epoch",2);b.pushKV("issued_ms",now);b.pushKV("expires_ms",now+3600000);b.pushKV("principals",principals);InstallPolicy(f.db,Signed("policy",b,f.owner),now);MeshTick(f.db,NowMs());});
    h.Test("mesh-tick-skips-revoked-worker-result",[&]{Fixture f;mesh_on(f,false);const auto package=Hash("remote package");auto rw=Object();rw.pushKV("enabled",true);rw.pushKV("packages",Strings({package}));rw.pushKV("compositions",Strings({f.composition}));f.local.pushKV("remote_work",rw);f.SaveLocal();
        auto wb=Common(f.realm,1,NowMs(),50000);wb.pushKV("composition",f.composition);wb.pushKV("capsule",f.capsule);wb.pushKV("package",package);wb.pushKV("purpose","verification");wb.pushKV("input_sha384",Hash("in"));wb.pushKV("expected_output_sha384",Hash("out"));wb.pushKV("target_host","any");wb.pushKV("nonce",Hex(RandomBytes(32)));wb.pushKV("max_output_bytes",static_cast<uint64_t>(8192));const auto work=f.Import(Signed("work",wb,f.owner));
        const auto receipt=f.Import(f.Receipt(f.composition,work,package,f.bob,"host-b",NowMs(),Hash("out")));auto rb=Common(f.realm,1,NowMs(),50000);rb.pushKV("work",work);rb.pushKV("purpose","verification");rb.pushKV("composition",f.composition);rb.pushKV("package",package);rb.pushKV("receipt",receipt);rb.pushKV("host","host-b");rb.pushKV("outcome","PASS");rb.pushKV("output_sha384",Hash("out"));rb.pushKV("output_bytes",static_cast<uint64_t>(100));f.Import(Signed("result",rb,f.bob));
        MeshTick(f.db,NowMs());f.Revoke(KeyId(f.bob.public_key));MeshTick(f.db,NowMs());});
    h.Test("maintain-freezes-channel-after-evaluator-revocation",[&]{Fixture f;mesh_on(f,true);Lifecycle l(f.db);auto m=f.Import(f.FollowMandate());l.Follow(m,NowMs());l.Stage(f.Import(f.Channel(1,f.capsule)),NowMs());f.Revoke(KeyId(f.bob.public_key));f.Revoke(m);
        Service svc(f.root);for(int i=0;i<100&&f.db.Meta("maintenance_at").empty()&&f.db.Meta("maintenance_error").empty();++i)std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const auto error=f.db.Meta("maintenance_error");Check(error.empty(),error.c_str());Check(Text(Lifecycle(f.db).Status()[0],"phase")=="frozen","channel not frozen");});
    // This node (f.db) coordinates a 2 s campaign signed by the owner key, which
    // is then revoked. MeshTick must skip the campaign instead of throwing, so
    // the Maintain loop still reaches Lifecycle::Tick.
    auto coordinate=[](Fixture& f,int64_t t0){auto cb=Common(f.realm,1,t0,300000);cb.pushKV("composition",f.composition);cb.pushKV("package",Hash("coordinated package"));cb.pushKV("suite",Hash("suite adversarial"));cb.pushKV("sample_commitment",Hash("samples adversarial"));cb.pushKV("gate","adversarial");cb.pushKV("interval_ms",static_cast<uint64_t>(2000));cb.pushKV("max_rounds",static_cast<uint64_t>(1000));
        const auto record=Signed("campaign",cb,f.owner);ImportRecord(f.db,f.policy,record,t0);const auto campaign=RecordId(record);
        auto settings=Object();settings.pushKV("enabled",true);settings.pushKV("max_evidence_age_ms",static_cast<uint64_t>(180000));settings.pushKV("allowed_campaigns",Strings({campaign}));
        auto id=Object();id.pushKV("public_key",Hex(f.owner.public_key));id.pushKV("secret_file",(f.root/"coordinator.key").string());WritePrivate(f.root/"coordinator.key",Hex(f.owner.secret_key));
        f.local.pushKV("host","owner-host");f.local.pushKV("identity",id);f.local.pushKV("continuous_security",settings);f.SaveLocal();return campaign;};
    h.Test("mesh-tick-skips-campaign-of-revoked-owner",[&]{Fixture f;const int64_t t0=NowMs();const auto campaign=coordinate(f,t0);MeshTick(f.db,t0);
        Check(f.db.Query("SELECT count(*) FROM mesh_rounds WHERE campaign=?",{campaign})[0][0]=="1","round 0 not scheduled");
        f.Revoke(KeyId(f.owner.public_key));MeshTick(f.db,t0+2500);
        Check(f.db.Query("SELECT count(*) FROM mesh_rounds WHERE campaign=?",{campaign})[0][0]=="1","round scheduled for a revoked owner's campaign");});
    h.Test("maintain-freezes-channel-after-owner-revocation",[&]{Fixture f;Lifecycle l(f.db);auto m=f.Import(f.FollowMandate());l.Follow(m,NowMs());const auto channel=f.Import(f.Channel(1,f.capsule));l.Stage(channel,NowMs());coordinate(f,NowMs());f.Revoke(m);f.Revoke(KeyId(f.owner.public_key));
        Service svc(f.root);for(int i=0;i<100&&f.db.Meta("maintenance_at").empty()&&f.db.Meta("maintenance_error").empty();++i)std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const auto error=f.db.Meta("maintenance_error");Check(error.empty(),error.c_str());Check(Text(Lifecycle(f.db).Status()[0],"phase")=="frozen","channel not frozen");});
    // Evaluator bob already holds a revocation of the capsule that alice
    // publishes. The peer evidence sync must still deliver the rest of the
    // closure instead of failing at the capsule on every response.
    h.Test("peer-sync-continues-past-revoked-record",[&]{Fixture f;PublishEvidenceClosure(f.db,f.capsule,NowMs());
        auto directory=f.temp.root/"peer-host-b";EnsurePrivateDirectory(directory);WritePrivate(directory/"root-pins.json",ReadFile(f.root/"root-pins.json"));
        Database remote(directory);InstallPolicy(remote,f.policy_record,NowMs());
        auto settings=f.local;settings.pushKV("host","host-b");auto peerid=Object();peerid.pushKV("public_key",Hex(f.bob.public_key));peerid.pushKV("secret_file",(directory/"peer.key").string());WritePrivate(directory/"peer.key",Hex(f.bob.secret_key));settings.pushKV("identity",peerid);WritePrivate(directory/"local.json",Canonical(settings));
        auto rb=Common(f.realm,1,NowMs());rb.pushKV("subject",f.capsule);rb.pushKV("sequence",1);rb.pushKV("reason","test incident");ImportRecord(remote,Policy::Load(remote,NowMs()),Signed("revocation",rb,f.owner,&f.second),NowMs());
        const auto alice=KeyId(f.alice.public_key);
        // Keep syncing until alice has actually offered the revoked capsule:
        // whether it comes before or after the composition depends on the
        // record ids, so stopping at the composition alone passed by chance.
        bool offered=false;
        for(int j=0;j<24&&!(offered&&remote.Has(f.composition));++j){auto request=MakePeerRequest(remote,alice,NowMs());auto reply=HandlePeerRequest(f.db,request,Hash("pin-b"),NowMs());
            for(const auto& record:reply["body"]["records"].getValues())offered=offered||RecordId(record)==f.capsule;
            AcceptPeerResponse(remote,reply,Hash("pin-a"),NowMs());}
        Check(offered,"revoked capsule never offered");Check(remote.Has(f.composition),"composition not received past the revoked capsule");Check(!remote.Has(f.capsule),"revoked capsule imported");
        Check(remote.Query("SELECT count(*) FROM peer_rejected WHERE peer=? AND id=?",{alice,f.capsule})[0][0]=="1","revoked capsule not recorded as rejected");
        Check(remote.Query("SELECT count(*) FROM peer_wants WHERE peer=? AND id=?",{alice,f.capsule})[0][0]=="0","revoked capsule still wanted");});
    h.Test("mesh-three-enrolled-hosts-continuous-security-lifecycle",[&]{
        std::string stage="begin";
        try {
        Check(!probe.empty(),"native worker required");
        Fixture f(probe);
        std::vector<std::string> campaigns;
        stage="campaign-plans";
        for(const auto& gate:GATES){
            const auto package=InstallPlan(f,gate);
            auto body=Common(f.realm,1,NowMs(),55000);
            body.pushKV("composition",f.composition);
            body.pushKV("package",package);
            body.pushKV("suite",Hash("suite "+gate));
            body.pushKV("sample_commitment",Hash("samples "+gate));
            body.pushKV("gate",gate);
            body.pushKV("interval_ms",static_cast<uint64_t>(30000));
            body.pushKV("max_rounds",static_cast<uint64_t>(2));
            auto campaign=f.Import(Signed("campaign",body,f.owner));
            MeshExport(f.db,campaign,NowMs());
            campaigns.push_back(campaign);
        }
        auto settings=Object();settings.pushKV("enabled",true);
        // The window has to outlast this fixture's own sandbox runs. Peer expiry
        // is checked below by rewriting seen_ms, not by this budget.
        settings.pushKV("max_evidence_age_ms",static_cast<uint64_t>(180000));
        settings.pushKV("allowed_campaigns",Strings(campaigns));
        auto worker_base=f.local;
        f.local.pushKV("host","owner-host");
        auto owner_id=Object();owner_id.pushKV("public_key",Hex(f.owner.public_key));
        owner_id.pushKV("secret_file",(f.root/"coordinator.key").string());
        WritePrivate(f.root/"coordinator.key",Hex(f.owner.secret_key));
        f.local.pushKV("identity",owner_id);f.local.pushKV("continuous_security",settings);f.SaveLocal();
        f.db.SetMeta("mesh_required","1"); // owner enrollment in this isolated fixture
        stage="coordinator-tick";
        MeshTick(f.db,NowMs());
        Check(f.db.Query("SELECT count(*) FROM mesh_rounds")[0][0]=="6","coordinator omitted scheduled work");
        struct Remote {
            fs::path path;
            std::unique_ptr<Database> db;
            std::string pin;
            std::string peer;
        };
        auto make_host=[&](const KeyPair& key,const std::string& host,const std::string& pin){
            Remote r;
            r.path=f.temp.root/(host+"-mesh");EnsurePrivateDirectory(r.path);
            WritePrivate(r.path/"root-pins.json",ReadFile(f.root/"root-pins.json"));
            r.db=std::make_unique<Database>(r.path);
            InstallPolicy(*r.db,f.policy_record,NowMs());
            auto local=worker_base;
            auto identity=Object();identity.pushKV("public_key",Hex(key.public_key));
            identity.pushKV("secret_file",(r.path/"identity.key").string());
            WritePrivate(r.path/"identity.key",Hex(key.secret_key));
            local.pushKV("identity",identity);local.pushKV("host",host);
            local.pushKV("continuous_security",settings);
            WritePrivate(r.path/"local.json",Canonical(local));
            r.pin=pin;r.peer=KeyId(key.public_key);
            return r;
        };
        stage="create-remote-dbs";
        auto a=make_host(f.alice,"host-a",Hash("pin-a"));
        auto b=make_host(f.bob,"host-b",Hash("pin-b"));
        auto coordinator=KeyId(f.owner.public_key);
        auto sync=[&](Database& client,const std::string& destination,
                      Database& server,const std::string& client_pin,const std::string& server_pin){
            const auto q=MeshRequest(client,destination,NowMs());
            const auto r=MeshHandle(server,q,client_pin,NowMs());
            MeshAccept(client,r,server_pin,NowMs());
        };
        for(Remote* remote:{&a,&b}){
            stage="receive-from-coordinator:"+remote->peer;
            for(int round=0;round<27;++round)sync(*remote->db,coordinator,f.db,remote->pin,Hash("pin-owner"));
            Check(remote->db->Has(f.composition),"model composition not distributed");
            for(const auto& campaign:campaigns)Check(remote->db->Has(campaign),"campaign not distributed");
            // Verified bytes are staged explicitly; this single-host fixture does
            // NOT stand in for actual P2P checkpoint acquisition.
            stage="resident:"+remote->peer;
            ImportResident(*remote->db,Policy::Load(*remote->db,NowMs()),f.composition,
                           f.temp.root/"source-base",1024*1024,NowMs());
            stage="execute:"+remote->peer;
            int executed=0;
            for(const auto& row:remote->db->Query("SELECT id FROM challenges")){
                auto ch=remote->db->Get(row[0]);
                if(!ch["body"]["campaign"].isStr())continue;
                auto camp=ch["body"]["campaign"].get_str();
                if(std::find(campaigns.begin(),campaigns.end(),camp)==campaigns.end())continue;
                auto report=EvaluateChallenge(*remote->db,row[0],NowMs());
                Check(Text(report["body"],"outcome")=="PASS","actual sandbox evaluation failed");
                ++executed;
            }
            Check(executed==6,"remote node did not execute six live security gates");
            stage="publish:"+remote->peer;
            MeshTick(*remote->db,NowMs()); // explicit owner-approved signed receipt publication
        }
        for(Remote* remote:{&a,&b}){
            stage="collect:"+remote->peer;
            for(int round=0;round<25;++round)sync(f.db,remote->peer,*remote->db,Hash("pin-owner"),remote->pin);
        }
        stage="live-quorum";
        MeshRequireLive(f.db,Policy::Load(f.db,NowMs()),f.capsule,NowMs());
        const auto live=MeshStatus(f.db,NowMs());
        Check(live["authenticated_recent_peer_sessions"].getInt<uint64_t>()==2,
              "signed evaluator liveness missing");
        // Two databases in one process are not a second organization or a release.
        Check(!live["qualified_production"].get_bool(),"one process must not qualify production");
        Check(!live["physical_host_independence_proven"].get_bool(),"enrollment is not physical-host evidence");
        f.db.Exec("UPDATE mesh_live SET seen_ms=1 WHERE peer=?",{b.peer});
        Reject([&]{MeshRequireLive(f.db,Policy::Load(f.db,NowMs()),f.capsule,NowMs());},
               "SEC_MESH_PEER_OFFLINE");
        stage="tool-fence";
        auto tool=f.Grant(); // enforced on every tool request, not just admission
        Reject([&]{Broker(f.db,Hex(RandomBytes(32))).Prepare(tool,f.Context(),f.ReadRequest(),NowMs());});
        } catch(const std::exception& e) { throw std::runtime_error(stage+": "+e.what()); }
    });
    h.Test("mesh-remote-bounded-work-two-signed-independent-receipts",[&]{
        std::string stage="setup";
        try {
        Check(!probe.empty(),"native sandbox worker required");
        Fixture f(probe);
        const auto plan=InstallPlan(f);
        const auto& manifest=f.local["evaluation_plans"][plan]["plan"];
        Json task_body=Common(f.realm,1,NowMs(),50000);
        task_body.pushKV("composition",f.composition);
        task_body.pushKV("capsule",f.capsule);
        task_body.pushKV("package",plan);
        task_body.pushKV("purpose","verification");
        task_body.pushKV("input_sha384",manifest["input_sha384"]);
        task_body.pushKV("expected_output_sha384",manifest["expected_output_sha384"]);
        task_body.pushKV("target_host","any");
        task_body.pushKV("nonce",Hex(RandomBytes(32)));
        task_body.pushKV("max_output_bytes",static_cast<uint64_t>(8192));
        const auto work=f.Import(Signed("work",task_body,f.owner));
        MeshExport(f.db,f.capsule,NowMs());MeshExport(f.db,work,NowMs());
        // Use a separately provisioned coordinator credential for peer exchanges.
        auto coordinator=Object();coordinator.pushKV("public_key",Hex(f.owner.public_key));
        coordinator.pushKV("secret_file",(f.root/"mesh-owner.key").string());
        WritePrivate(f.root/"mesh-owner.key",Hex(f.owner.secret_key));
        f.local.pushKV("host","owner-host");f.local.pushKV("identity",coordinator);f.SaveLocal();
        auto setup=[&](const KeyPair& key,const std::string& host)->std::unique_ptr<Database> {
            const auto path=f.temp.root/("remote-work-"+host);
            EnsurePrivateDirectory(path);WritePrivate(path/"root-pins.json",ReadFile(f.root/"root-pins.json"));
            auto db=std::make_unique<Database>(path);
            InstallPolicy(*db,f.policy_record,NowMs());
            auto local=f.local;local.pushKV("host",host);
            auto identity=Object();identity.pushKV("public_key",Hex(key.public_key));
            identity.pushKV("secret_file",(path/"identity.key").string());
            WritePrivate(path/"identity.key",Hex(key.secret_key));local.pushKV("identity",identity);
            auto remote_work=Object();remote_work.pushKV("enabled",true);
            remote_work.pushKV("packages",Strings({plan}));
            remote_work.pushKV("compositions",Strings({f.composition}));
            local.pushKV("remote_work",remote_work);
            auto evidence=Object();evidence.pushKV("enabled",true);
            evidence.pushKV("max_evidence_age_ms",static_cast<uint64_t>(20000));
            evidence.pushKV("allowed_campaigns",Strings({}));
            local.pushKV("continuous_security",evidence);
            // Every worker possesses its own independently stored input fixture.
            WritePrivate(path/"probe-input","probe");
            auto plans=local["evaluation_plans"];
            auto entry=plans[plan];entry.pushKV("input_file",(path/"probe-input").string());
            plans.pushKV(plan,entry);local.pushKV("evaluation_plans",plans);
            WritePrivate(path/"local.json",Canonical(local));
            db->SetMeta("runtime_available","1");
            return db;
        };
        auto a=setup(f.alice,"host-a");auto b=setup(f.bob,"host-b");
        const auto owner=KeyId(f.owner.public_key);
        auto sync=[&](Database& client,const std::string& destination,
                      Database& server,const std::string& client_pin,const std::string& server_pin){
            const auto request=MeshRequest(client,destination,NowMs());
            const auto response=MeshHandle(server,request,client_pin,NowMs());
            MeshAccept(client,response,server_pin,NowMs());
        };
        stage="gossip-work";
        for(const auto& pair:std::vector<std::pair<Database*,std::string>>{{a.get(),Hash("pin-a")},{b.get(),Hash("pin-b")}}){
            for(int i=0;i<26;++i){
                sync(*pair.first,owner,f.db,pair.second,Hash("pin-owner"));
                if(pair.first->Has(work)&&pair.first->Has(f.composition)&&pair.first->Has(f.capsule))break;
            }
            Check(pair.first->Has(work),"work not actually delivered to peer database");
            Check(pair.first->Has(f.composition),"immutable composition absent");
            ImportResident(*pair.first,Policy::Load(*pair.first,NowMs()),f.composition,
                           f.temp.root/"source-base",1024*1024,NowMs());
        }
        stage="real-sandbox-work";
        const auto result_a=ExecuteMeshWork(*a,work,NowMs());
        const auto result_b=ExecuteMeshWork(*b,work,NowMs());
        Check(Text(result_a["body"],"outcome")=="PASS"&&
              Text(result_b["body"],"outcome")=="PASS","remote actual native execution failed");
        Check(DigestField(result_a["body"],"output_sha384")==Hash(ExpectedProbe()),"wrong output A");
        Check(DigestField(result_b["body"],"output_sha384")==Hash(ExpectedProbe()),"wrong output B");
        Reject([&]{ExecuteMeshWork(*a,work,NowMs());},"SEC_WORK_REPLAY");
        MeshTick(*a,NowMs());MeshTick(*b,NowMs());
        stage="collect-signed-results";
        for(const auto& pair:std::vector<std::tuple<Database*,std::string,std::string>>{
            {a.get(),KeyId(f.alice.public_key),Hash("pin-a")},
            {b.get(),KeyId(f.bob.public_key),Hash("pin-b")}}){
            for(int i=0;i<26;++i){
                sync(f.db,std::get<1>(pair),*std::get<0>(pair),Hash("pin-owner"),std::get<2>(pair));
                if(f.db.Has(RecordId(result_a))&&f.db.Has(RecordId(result_b)))break;
            }
        }
        // Exact signed result IDs, not peer labels, must be imported.
        Check(f.db.Has(RecordId(result_a))&&f.db.Has(RecordId(result_b)),"independent result records absent");
        stage="check-quorum";
        auto quorum=VerifyMeshWorkQuorum(f.db,work,NowMs());
        Check(UInt(quorum,"enrolled_hosts")==2&&UInt(quorum,"enrolled_domains")==2,
              "two separately signed workers not verified");
        Check(!Boolean(quorum,"hardware_independence_verified"),"physical qualification incorrectly asserted");
        f.db.Exec("UPDATE mesh_live SET seen_ms=1 WHERE peer=?",{KeyId(f.bob.public_key)});
        Reject([&]{VerifyMeshWorkQuorum(f.db,work,NowMs());},"SEC_WORK_PEER_EXPIRED");
        } catch(const std::exception& e){throw std::runtime_error(stage+": "+e.what());}
    });
    h.Test("mesh-owner-consent-and-untrusted-artifact-denial",[&]{
        Fixture f;
        auto grant=f.Grant();Reject([&]{MeshExport(f.db,grant,NowMs());},"SEC_MESH_PRIVATE_KIND");
        Check(!MeshEnabled(f.db),"should not silently join mesh");
        auto settings=Object();settings.pushKV("enabled",true);
        settings.pushKV("max_evidence_age_ms",15000);
        settings.pushKV("allowed_campaigns",Strings({}));
        f.local.pushKV("continuous_security",settings);f.SaveLocal();
        Service svc(f.root);
        auto body=Common(f.realm,1,NowMs());body.pushKV("operation","mesh-enroll");body.pushKV("nonce",Hex(RandomBytes(32)));
        auto r=Object();r.pushKV("op","mesh-enroll");r.pushKV("record",Signed("control",body,f.owner));
        Check(Boolean(svc.Handle(r),"ok"),"owner enrollment failed");
        Check(f.db.Meta("mesh_required","0")=="1","enrollment not sticky");
        auto g=f.Grant();auto c=f.Context();auto req=f.ReadRequest();
        Reject([&]{Broker(f.db,Hex(RandomBytes(32))).Prepare(g,c,req,NowMs());},"SEC_MESH_INSUFFICIENT_LIVE_COVERAGE");
        auto status=svc.Handle(Object());Check(!Boolean(status,"ok"),"empty request accepted");
        Check(!Boolean(svc.Handle(r),"ok"),"replayed consent accepted");
    });
    h.Test("private-protocol-framing-and-out-of-order-denial",[&]{Temp t;Service service(t.root/"security");GuardProtocol protocol(service);const auto id=Hex(RandomBytes(16));const auto request=std::string("{\"op\":\"status\"}");Check(protocol.Handle("SEC2 BEGIN "+id+" "+std::to_string(request.size()))=="SEC2 READY "+id,"begin");auto hex=Hex(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(request.data()),request.size()));Check(protocol.Handle("SEC2 DATA "+id+" 1 "+hex).starts_with("ERR "),"out-of-order accepted");protocol.Handle("SEC2 BEGIN "+id+" "+std::to_string(request.size()));Check(protocol.Handle("SEC2 DATA "+id+" 0 "+hex).starts_with("SEC2 STORED "),"data");Check(protocol.Handle("SEC2 COMMIT "+id).starts_with("SEC2 RESPONSE "),"commit");Check(protocol.Handle("SEC2 READ "+id+" 0").starts_with("SEC2 BYTES "),"response");});
    h.Test("async-service-exec-and-delayed-release-fence",[&]{Fixture f;auto grant=f.Grant();Service service(f.root);auto request=Object();request.pushKV("op","prepare");request.pushKV("grant",grant);request.pushKV("context",f.Context());request.pushKV("request",f.ReadRequest());auto p=service.Handle(request);Check(Boolean(p,"ok"),p.write().c_str());request=Object();request.pushKV("op","execute");request.pushKV("secret",p["secret"]);request.pushKV("context",f.Context());request.pushKV("request",f.ReadRequest());auto submitted=service.Handle(request);Check(Boolean(submitted,"ok"),"submit");auto poll=Object();poll.pushKV("op","poll");poll.pushKV("job",submitted["job"]);Json result;for(int i=0;i<100;++i){result=service.Handle(poll);if(result["phase"].isStr()&&result["phase"].get_str()=="finished")break;std::this_thread::sleep_for(std::chrono::milliseconds(10));}Check(Text(result,"phase")=="finished","job did not finish");f.Revoke(grant);poll.pushKV("op","take");result=service.Handle(poll);Check(!Boolean(result["result"],"ok")&&!result["result"].exists("output_hex"),"revoked queued output released");});
    Json summary=Object();summary.pushKV("schema","BTX/ComponentSecurityTestResults/v1");summary.pushKV("passed",static_cast<uint64_t>(h.passed));summary.pushKV("failed",static_cast<uint64_t>(h.failed));summary.pushKV("physical_hosts",1);summary.pushKV("independent_organizations_verified",false);summary.pushKV("gpu_execution","NOT_RUN");summary.pushKV("whole_btxd_build","NOT_RUN");summary.pushKV("native_windows","NOT_RUN");summary.pushKV("native_macos","NOT_RUN");summary.pushKV("behavioral_backdoor_absence_proven",false);summary.pushKV("tests",h.results);if(!report.empty()){EnsurePrivateDirectory(report.parent_path());WritePrivate(report,Canonical(summary)+"\n",true);}std::cout<<"SUMMARY "<<Canonical(summary)<<'\n';return h.failed?1:0;
}

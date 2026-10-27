// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/trust.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <modelnet/security_v2/broker.h>
#include <limits>
namespace modelnet::security {
    namespace {
        constexpr std::array<const char*,6> GATES {
            "external-controls","outcome","revocation","rollback","privacy","adversarial"
        };
        void Fresh(const Json& b,int64_t now,uint64_t ttl) {
            auto issued=UInt(b,"issued_ms",INT64_MAX),expires=UInt(b,"expires_ms",INT64_MAX);
            Require(now>0&&issued<=static_cast<uint64_t>(now)&&expires>static_cast<uint64_t>(now)&&expires>issued&&expires-issued<=ttl,
            "SEC_EXPIRED_OR_FUTURE");
        }
        void InRealm(const Json& b,const Policy& p) {
            Require(DigestField(b,"realm")==p.realm&&UInt(b,"policy_epoch")==p.epoch,"SEC_POLICY_BINDING");
        }
        std::set<std::string> ToSet(const Json& x) {
            auto v=StringArray(x);
            return {
                v.begin(),v.end()
            };
        }
        void VerifyEach(const Json& e) {
            ValidateEnvelope(e);
            std::set<std::string> keys;
            for(const auto& s:e["signatures"].getValues()) {
                auto pk=Unhex(Text(s,"public_key",PK_BYTES*2),PK_BYTES);
                auto sig=Unhex(Text(s,"signature",SIG_BYTES*2),SIG_BYTES);
                Require(keys.insert(KeyId(pk)).second,"SEC_DUPLICATE_SIGNER");
                Require(Verify(Text(e,"kind"),e["body"],pk,sig),"SEC_SIGNATURE");
            }
        }
    }
    Policy Policy::Decode(const Json& e) {
        ValidateEnvelope(e);
        Require(Text(e,"kind")=="policy","SEC_POLICY_KIND");
        const auto& b=e["body"];
        Fields(b, {
            "realm","epoch","issued_ms","expires_ms","release_threshold","evaluator_domains","physical_hosts","evidence_ttl_ms",
            "canary_ms","trial_limit","principals","gates"
        });
        Policy p;
        p.envelope=e;
        p.id=RecordId(e);
        p.realm=DigestField(b,"realm");
        p.epoch=UInt(b,"epoch",INT64_MAX);
        Require(p.epoch>0,"SEC_POLICY_EPOCH");
        p.expires=UInt(b,"expires_ms",INT64_MAX);
        p.release_threshold=UInt(b,"release_threshold",MAX_SIGNATURES);
        p.evaluator_domains=UInt(b,"evaluator_domains",16);
        p.physical_hosts=UInt(b,"physical_hosts",16);
        p.evidence_ttl_ms=UInt(b,"evidence_ttl_ms",7ull*86400000);
        p.canary_ms=UInt(b,"canary_ms",7ull*86400000);
        p.trial_limit=UInt(b,"trial_limit",1024);
        Require(p.release_threshold>=1&&p.evaluator_domains>=2&&p.physical_hosts>=2&&p.evidence_ttl_ms>=1000&&p.canary_ms>=1000&&p.trial_limit>=1,
        "SEC_POLICY_LIMIT");
        p.gates=StringArray(b["gates"],6);
        Require(p.gates.size()==6,"SEC_GATES");
        for(auto gate:GATES)Require(std::find(p.gates.begin(),p.gates.end(),gate)!=p.gates.end(),"SEC_GATES");
        Require(b["principals"].isArray()&&b["principals"].size()<=128,"SEC_PRINCIPALS");
        for(const auto& row:b["principals"].getValues()) {
            Fields(row, {
                "public_key","roles","domain","host","transport_pin"
            });
            Principal principal;
            principal.key=Unhex(Text(row,"public_key",PK_BYTES*2),PK_BYTES);
            auto id=KeyId(principal.key);
            principal.roles=ToSet(row["roles"]);
            principal.domain=Text(row,"domain",128);
            principal.host=Text(row,"host",128);
            Require(row["transport_pin"].isStr(),"SEC_PIN");
            principal.transport_pin=row["transport_pin"].get_str();
            Require(principal.transport_pin.empty()||IsHash(principal.transport_pin),"SEC_PIN");
            static const std::set<std::string> roles {
                "owner","publisher","release","evaluator","revoker","coordinator","worker","peer","witness"
            };
            for(const auto& role:principal.roles)Require(roles.contains(role),"SEC_ROLE");
            Require(p.principals.emplace(id,std::move(principal)).second,"SEC_DUPLICATE_PRINCIPAL");
        }
        return p;
    }
    void VerifyPinnedPolicy(const Json& e,const Json& roots) {
        Fields(roots, {
            "schema","keys","threshold"
        });
        Require(Text(roots,"schema")=="BTX/SecurityRootPins/v1","SEC_ROOT_VERSION");
        auto pins=ToSet(roots["keys"]);
        const auto threshold=UInt(roots,"threshold",MAX_SIGNATURES);
        Require(threshold>=1&&threshold<=pins.size(),"SEC_ROOT_THRESHOLD");
        for(const auto& p:pins)Require(IsHash(p),"SEC_ROOT_PIN");
        VerifyEach(e);
        std::set<std::string> counted;
        for(const auto& s:e["signatures"].getValues()) {
            auto id=KeyId(Unhex(Text(s,"public_key",PK_BYTES*2),PK_BYTES));
            if(pins.contains(id))counted.insert(id);
        }
        Require(counted.size()>=threshold,"SEC_ROOT_SIGNATURES");
    }
    Policy Policy::Load(Database& db,int64_t now) {
        const auto roots=Parse(ReadFile(db.Root()/"root-pins.json",MAX_RECORD,true));
        const auto active=db.Meta("active_policy");
        Require(IsHash(active),"SEC_POLICY_ABSENT");
        auto e=db.Get(active);
        VerifyPinnedPolicy(e,roots);
        auto p=Decode(e);
        Fresh(e["body"],now,366ull*86400000);
        Require(p.epoch>=ParseUInt(db.Meta("policy_epoch","0")),"SEC_POLICY_ROLLBACK");
        return p;
    }
    const Principal& Policy::Find(const std::string& id,std::string_view role,Database& db,int64_t now)const {
        Require(static_cast<uint64_t>(now)<expires,"SEC_POLICY_EXPIRED");
        auto i=principals.find(id);
        Require(i!=principals.end()&&i->second.roles.contains(std::string(role)),"SEC_UNTRUSTED_ROLE");
        Require(!db.Revoked(id,now),"SEC_SIGNER_REVOKED");
        return i->second;
    }
    std::vector<std::string> Policy::Check(const Json& e,std::string_view role,Database& db,int64_t now,size_t threshold)const {
        VerifyEach(e);
        std::vector<std::string> counted;
        for(const auto& s:e["signatures"].getValues()) {
            auto id=KeyId(Unhex(Text(s,"public_key",PK_BYTES*2),PK_BYTES));
            auto i=principals.find(id);
            if(i==principals.end()||!i->second.roles.contains(std::string(role)))continue;
            Find(id,role,db,now);
            counted.push_back(id);
        }
        Require(counted.size()>=threshold,"SEC_SIGNATURE_THRESHOLD");
        return counted;
    }
    void InstallPolicy(Database& db,const Json& e,int64_t now) {
        auto roots=Parse(ReadFile(db.Root()/"root-pins.json",MAX_RECORD,true));
        VerifyPinnedPolicy(e,roots);
        auto next=Policy::Decode(e);
        Fresh(e["body"],now,366ull*86400000);
        Database::Transaction tx(db);
        db.CheckClock(now);
        auto old_id=db.Meta("active_policy");
        if(!old_id.empty()) {
            auto old=Policy::Decode(db.Get(old_id));
            Require(next.realm==old.realm&&next.epoch>old.epoch,"SEC_POLICY_ROLLBACK");
            // fixed root pins require an offline, separately reviewed recovery to change.
            old.Check(e,"owner",db,now,1);
        }
        db.Put(e);
        db.SetMeta("active_policy",next.id);
        db.SetMeta("policy_epoch",std::to_string(next.epoch));
        db.Exec("UPDATE permits SET phase='revoked' WHERE phase='prepared'");
        db.Event("policy-installed",next.id,Object());
        tx.Commit();
    }
    void ValidateComposition(const Json& b) {
        Fields(b, {
            "realm","policy_epoch","files","runtime","sandbox","tool_schema","system_prompt","parents","contributors",
            "license","architecture","visibility"
        });
        DigestField(b,"realm");
        UInt(b,"policy_epoch");
        for(auto n: {
            "runtime","sandbox","tool_schema","system_prompt"
        })DigestField(b,n);
        Text(b,"license",256);
        Text(b,"architecture",128);
        Require(Text(b,"visibility")=="private"||Text(b,"visibility")=="public","SEC_VISIBILITY");
        for(const auto& x:StringArray(b["parents"],32))Require(IsHash(x),"SEC_PARENT");
        for(const auto& x:StringArray(b["contributors"],128))Require(IsHash(x),"SEC_CONTRIBUTOR");
        Require(b["files"].isArray()&&b["files"].size()>0&&b["files"].size()<=512,"SEC_COMPOSITION_FILES");
        std::set<std::string> paths;
        bool weights=false,tokenizer=false,config=false,chat=false;
        uint64_t total=0;
        for(const auto& f:b["files"].getValues()) {
            Fields(f, {
                "path","sha384","bytes","role"
            });
            auto path=Text(f,"path",1024);
            auto portable_key=path;
            std::transform(portable_key.begin(),portable_key.end(),portable_key.begin(),[](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            Require(IsPortablePath(path)&&!IsCredentialPath(path)&&paths.insert(portable_key).second,"SEC_COMPOSITION_PATH");
            DigestField(f,"sha384");
            auto bytes=UInt(f,"bytes",1ull<<44);
            Require(total<=(1ull<<44)-bytes,"SEC_COMPOSITION_SIZE");
            total+=bytes;
            auto role=Text(f,"role",32);
            Require(role=="weights"||role=="tokenizer"||role=="config"||role=="chat_template"||role=="adapter","SEC_COMPONENT_ROLE");
            weights|=role=="weights";
            tokenizer|=role=="tokenizer";
            config|=role=="config";
            chat|=role=="chat_template";
            auto lower=path;
            std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            Require(!lower.ends_with(".py")&&!lower.ends_with(".pkl")&&!lower.ends_with(".pickle")&&!lower.ends_with(".pt")&&!lower.ends_with(".so")&&!lower.ends_with(".dll"),
            "SEC_EXECUTABLE_MODEL_COMPONENT");
        }
        Require(weights&&tokenizer&&config&&chat,"SEC_COMPOSITION_INCOMPLETE");
    }
    void ImportRecord(Database& db,const Policy& p,const Json& e,int64_t now,bool peer) {
        ValidateEnvelope(e);
        auto kind=Text(e,"kind");
        const auto& b=e["body"];
        InRealm(b,p);
        const auto id=RecordId(e);
        Require(!db.Revoked(id,now),"SEC_RECORD_REVOKED");
        if(kind=="composition") {
            p.Check(e,"publisher",db,now);
            ValidateComposition(b);
        }
        else if(kind=="evaluation") {
            p.Check(e,"evaluator",db,now);
            Fields(b, {
                "realm","policy_epoch","composition","challenge","campaign","suite","sample_commitment","runtime","sandbox",
                "gate","outcome","cases","execution_receipt","output_digest","issued_ms","expires_ms","host","physical_host_evidence",
                "limitations"
            });
            Fresh(b,now,p.evidence_ttl_ms);
            for(auto n: {
                "composition","challenge","campaign","suite","sample_commitment","runtime","sandbox","execution_receipt",
                "output_digest"
            })DigestField(b,n);
            Require(std::find(p.gates.begin(),p.gates.end(),Text(b,"gate"))!=p.gates.end(),"SEC_GATE");
            auto outcome=Text(b,"outcome");
            Require(outcome=="PASS"||outcome=="FAIL"||outcome=="BLOCKED"||outcome=="NOT_RUN","SEC_OUTCOME");
            UInt(b,"cases",10000000);
            Text(b,"host",128);
            Text(b,"physical_host_evidence",128);
            StringArray(b["limitations"],64);
        }
        else if(kind=="capsule") {
            p.Check(e,"release",db,now,p.release_threshold);
            Fields(b, {
                "realm","policy_epoch","composition","evaluations","profile","issued_ms","expires_ms"
            });
            Fresh(b,now,p.evidence_ttl_ms);
            DigestField(b,"composition");
            auto refs=StringArray(b["evaluations"],256);
            for(const auto& x:refs)Require(IsHash(x),"SEC_EVIDENCE_REF");
            auto profile=Text(b,"profile");
            Require(profile=="inference-only"||profile=="restricted-tools","SEC_PROFILE");
        }
        else if(kind=="revocation") {
            p.Check(e,"revoker",db,now,p.release_threshold);
            Fields(b, {
                "realm","policy_epoch","subject","sequence","reason","issued_ms","expires_ms"
            });
            Fresh(b,now,p.evidence_ttl_ms);
            DigestField(b,"subject");
            Require(UInt(b,"sequence",INT64_MAX)>0,"SEC_SEQUENCE");
            Text(b,"reason",256);
        }
        else if(kind=="grant") {
            Require(!peer,"SEC_PEER_CANNOT_GRANT");
            p.Check(e,"owner",db,now);
            ValidateGrant(b);
            Fresh(b,now,86400000);
        }
        else if(kind=="channel") {
            p.Check(e,"release",db,now,p.release_threshold);
            Fields(b, {
                "realm","policy_epoch","name","sequence","capsule","previous","issued_ms","expires_ms"
            });
            Fresh(b,now,p.evidence_ttl_ms);
            Text(b,"name",128);
            Require(UInt(b,"sequence",INT64_MAX)>0,"SEC_SEQUENCE");
            DigestField(b,"capsule");
            Require(b["previous"].isStr()&&(b["previous"].get_str().empty()||IsHash(b["previous"].get_str())),"SEC_PREVIOUS");
        }
        else if(kind=="mandate") {
            Require(!peer,"SEC_PEER_CANNOT_MANDATE");
            p.Check(e,"owner",db,now);
            Fields(b, {
                "realm","policy_epoch","channel","profile","runtimes","tool_schemas","automatic_follow","issued_ms","expires_ms"
            });
            Fresh(b,now,366ull*86400000);
            Text(b,"channel",128);
            Require(Text(b,"profile")=="inference-only"||Text(b,"profile")=="restricted-tools","SEC_PROFILE");
            Boolean(b,"automatic_follow");
            for(auto field: {
                "runtimes","tool_schemas"
            }) {
                auto values=StringArray(b[field],32);
                Require(!values.empty(),"SEC_MANDATE_EMPTY");
                for(const auto& value:values)Require(IsHash(value),"SEC_MANDATE_DIGEST");
            }
        }
        else if(kind=="control") {
            Require(!peer,"SEC_PEER_CANNOT_CONTROL");
            p.Check(e,"owner",db,now);
            Fields(b, {
                "realm","policy_epoch","operation","nonce","issued_ms","expires_ms"
            });
            Fresh(b,now,60000);
            Require(Text(b,"operation")=="resume"||Text(b,"operation")=="mesh-enroll","SEC_CONTROL");
            Require(Unhex(Text(b,"nonce",64),32).size()==32,"SEC_NONCE");
        }
        else if(kind=="campaign") {
            p.Check(e,"owner",db,now);
            Fields(b,{"realm","policy_epoch","composition","package","suite","sample_commitment","gate",
                      "interval_ms","max_rounds","issued_ms","expires_ms"});
            Fresh(b,now,366ull*86400000);
            for(auto field:{"composition","package","suite","sample_commitment"})DigestField(b,field);
            Require(std::find(p.gates.begin(),p.gates.end(),Text(b,"gate"))!=p.gates.end(),"SEC_GATE");
            Require(UInt(b,"interval_ms",86400000)>=2000,"SEC_CAMPAIGN_INTERVAL");
            Require(UInt(b,"max_rounds",100000)>0,"SEC_CAMPAIGN_ROUNDS");
        }
        else if(kind=="challenge") {
            p.Check(e,"coordinator",db,now);
            Fields(b, {
                "realm","policy_epoch","composition","campaign","suite","sample_commitment","package","gate","trial_limit",
                "issued_ms","expires_ms"
            });
            Fresh(b,now,p.evidence_ttl_ms);
            for(auto n: {
                "composition","campaign","suite","sample_commitment","package"
            })DigestField(b,n);
            Require(std::find(p.gates.begin(),p.gates.end(),Text(b,"gate"))!=p.gates.end(),"SEC_GATE");
            Require(UInt(b,"trial_limit",p.trial_limit)>0,"SEC_TRIAL_LIMIT");
        }
        else if(kind=="work") {
            p.Check(e,"coordinator",db,now);
            Fields(b,{"realm","policy_epoch","composition","capsule","package","purpose","input_sha384",
                      "expected_output_sha384","target_host","nonce","max_output_bytes","issued_ms","expires_ms"});
            Fresh(b,now,p.evidence_ttl_ms);
            for(auto f:{"composition","capsule","package","input_sha384","expected_output_sha384"})DigestField(b,f);
            const auto purpose=Text(b,"purpose",32);
            Require(purpose=="inference"||purpose=="training"||purpose=="verification","SEC_WORK_PURPOSE");
            Text(b,"target_host",128);
            Require(Unhex(Text(b,"nonce",64),32).size()==32,"SEC_WORK_NONCE");
            Require(UInt(b,"max_output_bytes",16384)>0,"SEC_WORK_OUTPUT_BOUND");
        }
        else if(kind=="result") {
            p.Check(e,"worker",db,now);
            Fields(b,{"realm","policy_epoch","work","purpose","composition","package","receipt","host",
                      "outcome","output_sha384","output_bytes","issued_ms","expires_ms"});
            Fresh(b,now,p.evidence_ttl_ms);
            for(auto f:{"work","composition","package","receipt","output_sha384"})DigestField(b,f);
            Text(b,"host",128);Text(b,"purpose",32);
            const auto outcome=Text(b,"outcome",32);
            Require(outcome=="PASS"||outcome=="FAIL"||outcome=="BLOCKED","SEC_WORK_RESULT_OUTCOME");
            UInt(b,"output_bytes",16384);
        }
        else if(kind=="lease") {
            p.Check(e,"coordinator",db,now);
            Fields(b, {
                "realm","policy_epoch","task","worker","nonce","issued_ms","expires_ms"
            });
            Fresh(b,now,60000);
            DigestField(b,"task");
            DigestField(b,"worker");
            Require(Unhex(Text(b,"nonce",64),32).size()==32,"SEC_NONCE");
        }
        else if(kind=="receipt") {
            p.Check(e,"worker",db,now);
            Fields(b, {
                "realm","policy_epoch","job","request","package","composition","runtime","sandbox","outcome","output_digest",
                "output_bytes","issued_ms","expires_ms","host","limits","dispatched"
            });
            Fresh(b,now,p.evidence_ttl_ms);
            for(auto n: {
                "job","request","package","composition","runtime","sandbox","output_digest"
            })DigestField(b,n);
            Text(b,"outcome",64);
            Text(b,"host",128);
            UInt(b,"output_bytes",64*1024*1024);
            Require(b["limits"].isObject(),"SEC_LIMITS");
            Boolean(b,"dispatched");
        }
        else if(kind=="anchor") {
            p.Check(e,"witness",db,now);
            Fields(b, {
                "realm","policy_epoch","journal_head","issued_ms","expires_ms"
            });
            Fresh(b,now,p.evidence_ttl_ms);
            DigestField(b,"journal_head");
        }
        else throw Error("SEC_RECORD_NOT_IMPORTABLE");
        Database::Transaction tx(db);
        db.CheckClock(now);
        std::string visibility="private";
        if(kind=="composition")visibility=Text(b,"visibility");
        db.Put(e,visibility);
        if(kind=="composition")for(const auto& parent:StringArray(b["parents"],32))db.LinkParent(id,parent);
        if(kind=="revocation") {
            db.Revoke(DigestField(b,"subject"),id,UInt(b,"sequence",INT64_MAX),now);
            db.Exec("UPDATE permits SET phase='revoked' WHERE phase='prepared'");
        }
        if(kind=="challenge") {
            const auto campaign=DigestField(b,"campaign"),candidate=DigestField(b,"composition");
            auto present=db.Query("SELECT candidate FROM trials WHERE campaign=? AND candidate=?", {
                campaign,candidate
            });
            auto count=db.Query("SELECT count(*) FROM trials WHERE campaign=?", {
                campaign
            });
            Require(!present.empty()||ParseUInt(count[0][0])<UInt(b,"trial_limit",p.trial_limit),"SEC_TRIAL_EXHAUSTED");
            db.Exec("INSERT OR IGNORE INTO trials(campaign,candidate) VALUES(?,?)", {
                campaign,candidate
            });
            db.Exec("INSERT OR IGNORE INTO challenges(id,campaign,candidate,phase) VALUES(?,?,?,'queued')", {
                id,campaign,candidate
            });
        }
        db.Event("record-imported",id,Object());
        tx.Commit();
    }
    Admission AdmitCapsule(Database& db,const Policy& p,const std::string& id,int64_t now) {
        Require(!db.AncestryRevoked(id,now),"SEC_QUARANTINE");
        auto capsule=db.Get(id);
        Require(Text(capsule,"kind")=="capsule","SEC_CAPSULE_KIND");
        p.Check(capsule,"release",db,now,p.release_threshold);
        const auto& c=capsule["body"];
        InRealm(c,p);
        Fresh(c,now,p.evidence_ttl_ms);
        Admission out;
        out.capsule_id=id;
        out.composition_id=DigestField(c,"composition");
        out.policy_id=p.id;
        out.epoch=p.epoch;
        out.valid_until=std::min(UInt(c,"expires_ms",INT64_MAX),p.expires);
        out.profile=Text(c,"profile");
        Require(out.profile=="inference-only"||out.profile=="restricted-tools","SEC_PROFILE");
        auto composition=db.Get(out.composition_id);
        Require(Text(composition,"kind")=="composition","SEC_COMPOSITION_KIND");
        ValidateComposition(composition["body"]);
        InRealm(composition["body"],p);
        auto authors=p.Check(composition,"publisher",db,now);
        const auto& b=composition["body"];
        out.runtime=DigestField(b,"runtime");
        out.tool_schema=DigestField(b,"tool_schema");
        Require(!db.AncestryRevoked(out.composition_id,now),"SEC_QUARANTINE");
        std::set<std::string> excluded(authors.begin(),authors.end());
        for(const auto& key:StringArray(b["contributors"],128))excluded.insert(key);
        // Negative outcomes are read from the entire retained candidate history, not
        // just the favorable references chosen by the capsule's publisher.
        for(const auto& r:db.Query("SELECT envelope FROM objects WHERE kind='evaluation'")) {
            auto e=Parse(r[0]);
            const auto& report=e["body"];
            if(report["composition"].isStr()&&report["composition"].get_str()==out.composition_id&&report["outcome"].isStr()&&report["outcome"].get_str()=="FAIL") {
                // A signature valid under this policy is negative evidence even when
                // the report's positive freshness window has elapsed.
                auto keys=p.Check(e,"evaluator",db,now);
                if(!keys.empty())throw Error("SEC_NEGATIVE_EVIDENCE");
            }
        }
        struct Coverage {
            std::set<std::string> keys,domains,hosts;
            std::string suite,sample,campaign;
        };
        std::map<std::string,Coverage> coverage;
        for(const auto& rid:StringArray(c["evaluations"],256)) {
            Require(!db.Revoked(rid,now),"SEC_EVIDENCE_REVOKED");
            auto e=db.Get(rid);
            Require(Text(e,"kind")=="evaluation","SEC_EVIDENCE_KIND");
            const auto& r=e["body"];
            InRealm(r,p);
            Fresh(r,now,p.evidence_ttl_ms);
            Require(DigestField(r,"composition")==out.composition_id&&DigestField(r,"runtime")==out.runtime&&DigestField(r,
            "sandbox")==DigestField(b,"sandbox"),"SEC_EVIDENCE_BINDING");
            Require(Text(r,"outcome")=="PASS"&&UInt(r,"cases",10000000)>0,"SEC_EVIDENCE_NOT_PASS");
            auto signers=p.Check(e,"evaluator",db,now);
            Require(signers.size()==1,"SEC_EVALUATION_ONE_EXECUTOR");
            auto signer=signers[0];
            Require(!excluded.contains(signer),"SEC_AUTHOR_EVALUATOR");
            const auto& principal=p.Find(signer,"evaluator",db,now);
            for(const auto& author:excluded) {
                auto it=p.principals.find(author);
                if(it!=p.principals.end())Require(it->second.domain!=principal.domain,"SEC_AUTHOR_DOMAIN");
            }
            Require(Text(r,"host",128)==principal.host&&Text(r,"physical_host_evidence",128)==principal.host,
            "SEC_HOST_ENROLLMENT");
            auto challenge=db.Get(DigestField(r,"challenge"));
            Require(Text(challenge,"kind")=="challenge","SEC_CHALLENGE_KIND");
            p.Check(challenge,"coordinator",db,now);
            const auto& ch=challenge["body"];
            InRealm(ch,p);
            for(auto field: {
                "composition","campaign","suite","sample_commitment","gate"
            })Require(Text(ch,field)==Text(r,field),"SEC_CHALLENGE_BINDING");
            Require(UInt(r,"issued_ms",INT64_MAX)>=UInt(ch,"issued_ms",INT64_MAX)&&UInt(r,"issued_ms",INT64_MAX)<UInt(ch,
            "expires_ms",INT64_MAX),"SEC_CHALLENGE_TIME");
            // A report cannot qualify merely by naming an arbitrary receipt hash.
            // Bind the signed execution receipt to this challenge and this executor.
            const auto receipt_id=DigestField(r,"execution_receipt");
            Require(!db.Revoked(receipt_id,now),"SEC_RECEIPT_REVOKED");
            const auto receipt=db.Get(receipt_id);
            Require(Text(receipt,"kind")=="receipt","SEC_RECEIPT_KIND");
            const auto workers=p.Check(receipt,"worker",db,now);
            Require(workers.size()==1 && workers[0]==signer,"SEC_RECEIPT_EXECUTOR");
            const auto& rb=receipt["body"];
            InRealm(rb,p);
            Fresh(rb,now,p.evidence_ttl_ms);
            for(auto field: {
                "composition","runtime","sandbox","output_digest","host"
            })
            Require(Text(rb,field)==Text(r,field),"SEC_RECEIPT_BINDING");
            Require(DigestField(rb,"request")==DigestField(r,"challenge") &&
            DigestField(rb,"package")==DigestField(ch,"package") &&
            Boolean(rb,"dispatched") && Text(rb,"outcome")=="PASS",
            "SEC_RECEIPT_NOT_EXECUTED");
            Require(UInt(rb,"issued_ms",INT64_MAX)>=UInt(ch,"issued_ms",INT64_MAX) &&
            UInt(rb,"issued_ms",INT64_MAX)<=UInt(r,"issued_ms",INT64_MAX),
            "SEC_RECEIPT_TIME");
            out.valid_until=std::min(out.valid_until,UInt(rb,"expires_ms",INT64_MAX));
            const auto gate=Text(r,"gate");
            Require(std::find(p.gates.begin(),p.gates.end(),gate)!=p.gates.end(),"SEC_GATE");
            auto& item=coverage[gate];
            auto suite=DigestField(r,"suite"),sample=DigestField(r,"sample_commitment"),campaign=DigestField(r,"campaign");
            if(item.keys.empty()) {
                item.suite=suite;
                item.sample=sample;
                item.campaign=campaign;
            }
            else Require(item.suite==suite&&item.sample==sample&&item.campaign==campaign,"SEC_EVIDENCE_MIX");
            Require(item.keys.insert(signer).second,"SEC_DUPLICATE_EVALUATOR");
            item.domains.insert(principal.domain);
            item.hosts.insert(principal.host);
            out.evaluator_keys.insert(signer);
            out.domains.insert(principal.domain);
            out.hosts.insert(principal.host);
            out.valid_until=std::min(out.valid_until,UInt(r,"expires_ms",INT64_MAX));
        }
        for(const auto& gate:p.gates) {
            auto it=coverage.find(gate);
            Require(it!=coverage.end()&&it->second.domains.size()>=p.evaluator_domains&&it->second.hosts.size()>=p.physical_hosts,
            "SEC_INDEPENDENT_COVERAGE");
        }
        return out;
    }
    Json SecurityStatus(Database& db,const Policy& p,const std::string& subject,int64_t now) {
        Json out=Object();
        out.pushKV("schema","BTX/ModelSecurityStatus/v1");
        out.pushKV("subject",subject);
        out.pushKV("policy",p.id);
        out.pushKV("policy_epoch",p.epoch);
        out.pushKV("automatic_spend_atoms","0");
        out.pushKV("behavioral_safety_proven",false);
        out.pushKV("physical_identity_basis","OWNER_ENROLLMENT_NOT_CRYPTOGRAPHIC_INDEPENDENCE");
        try {
            auto a=AdmitCapsule(db,p,subject,now);
            out.pushKV("admitted",true);
            out.pushKV("composition",a.composition_id);
            out.pushKV("profile",a.profile);
            out.pushKV("valid_until_ms",a.valid_until);
            out.pushKV("evaluator_domains",static_cast<uint64_t>(a.domains.size()));
            out.pushKV("enrolled_hosts",static_cast<uint64_t>(a.hosts.size()));
        }
        catch(const Error& e) {
            out.pushKV("admitted",false);
            out.pushKV("reason",e.code);
        }
        return out;
    }
}
// namespace modelnet::security

// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/lifecycle.h>
#include <modelnet/security_v2/mesh.h>
#include <algorithm>
namespace modelnet::security {
    namespace {
        bool Listed(const Json& array,const std::string& value) {
            auto list=StringArray(array,32);
            return std::find(list.begin(),list.end(),value)!=list.end();
        }
        void Current(const Json& body,const Policy& p,int64_t now) {
            Require(DigestField(body,"realm")==p.realm&&UInt(body,"policy_epoch")==p.epoch&&
            UInt(body,"issued_ms",INT64_MAX)<=static_cast<uint64_t>(now)&&
            UInt(body,"expires_ms",INT64_MAX)>static_cast<uint64_t>(now),"SEC_CHANNEL_POLICY_OR_TIME");
        }
    }
    void Lifecycle::CheckMandate(const Policy& p,const Json& e,const Admission& a,int64_t now) {
        Require(Text(e,"kind")=="mandate"&&!m_db.Revoked(RecordId(e),now),"SEC_FOLLOW_MANDATE");
        p.Check(e,"owner",m_db,now);
        const auto& b=e["body"];
        Current(b,p,now);
        Require(Boolean(b,"automatic_follow"),"SEC_AUTOMATIC_FOLLOW_NOT_GRANTED");
        Require(Listed(b["runtimes"],a.runtime)&&Listed(b["tool_schemas"],a.tool_schema),"SEC_UPDATE_AUTHORITY_EXPANSION");
        Require(a.profile=="inference-only"||Text(b,"profile")=="restricted-tools","SEC_UPDATE_PRIVILEGE_EXPANSION");
    }
    bool Lifecycle::Eligible(const Policy& p,const std::string& capsule,int64_t now) {
        if(capsule.empty())return false;
        try {
            (void)AdmitCapsule(m_db,p,capsule,now);
            if(m_db.Meta("mesh_required","0")=="1")MeshRequireLive(m_db,p,capsule,now);
            return true;
        }
        catch(...) {
            return false;
        }
    }
    void Lifecycle::Follow(const std::string& id,int64_t now) {
        auto p=Policy::Load(m_db,now);
        auto e=m_db.Get(id);
        Require(Text(e,"kind")=="mandate","SEC_FOLLOW_MANDATE");
        p.Check(e,"owner",m_db,now);
        const auto& b=e["body"];
        Current(b,p,now);
        const auto name=Text(b,"channel",128);
        Require(!m_db.Revoked(id,now),"SEC_FOLLOW_REVOKED");
        Database::Transaction tx(m_db);
        m_db.CheckClock(now);
        auto old=m_db.Query("SELECT mandate_id FROM channels WHERE name=?", {
            name
        });
        if(!old.empty()&&old[0][0]==id) {
            tx.Commit();
            return;
        }
        // A new owner mandate may narrow authority; it never resets channel sequence.
        m_db.Exec("INSERT INTO channels(name,sequence,phase,policy_epoch,mandate_id) VALUES(?,0,'awaiting',?,?) "
        "ON CONFLICT(name) DO UPDATE SET mandate_id=excluded.mandate_id,policy_epoch=excluded.policy_epoch,"
        "phase='awaiting',candidate='',runtime_observed=''", {
            name,std::to_string(p.epoch),id
        });
        m_db.Event("channel-followed",name,Object());
        tx.Commit();
    }
    void Lifecycle::Stage(const std::string& update_id,int64_t now) {
        auto p=Policy::Load(m_db,now);
        auto update=m_db.Get(update_id);
        Require(Text(update,"kind")=="channel","SEC_CHANNEL_KIND");
        p.Check(update,"release",m_db,now,p.release_threshold);
        const auto& b=update["body"];
        Current(b,p,now);
        Require(!m_db.Revoked(update_id,now),"SEC_UPDATE_REVOKED");
        const auto name=Text(b,"name",128),capsule=DigestField(b,"capsule");
        auto admission=AdmitCapsule(m_db,p,capsule,now);
        (void)VerifyResident(m_db,admission.composition_id);
        Database::Transaction tx(m_db);
        m_db.CheckClock(now);
        auto rows=m_db.Query("SELECT sequence,active,phase,update_id,mandate_id FROM channels WHERE name=?",
        {
            name
        });
        Require(rows.size()==1,"SEC_CHANNEL_NOT_FOLLOWED");
        const auto& old=rows[0];
        const auto seq=UInt(b,"sequence",INT64_MAX),current=ParseUInt(old[0]);
        if(seq==current) {
            if(old[3]==update_id) {
                tx.Commit();
                return;
            }
            m_db.Exec("UPDATE channels SET phase='frozen' WHERE name=?", {
                name
            });
            m_db.Event("channel-equivocation",name,Object());
            tx.Commit();
            throw Error("SEC_CHANNEL_EQUIVOCATION");
        }
        Require(seq>current&&seq-current==1,"SEC_CHANNEL_SEQUENCE_GAP_OR_ROLLBACK");
        Require(old[2]!="canary","SEC_CANARY_IN_PROGRESS");
        Require(b["previous"].isStr()&&b["previous"].get_str()==old[1],"SEC_CHANNEL_PREVIOUS");
        auto mandate=m_db.Get(old[4]);
        CheckMandate(p,mandate,admission,now);
        Require(Text(mandate["body"],"channel",128)==name,"SEC_FOLLOW_MANDATE");
        Require(admission.valid_until>static_cast<uint64_t>(now)+p.canary_ms,"SEC_CANARY_EVIDENCE_TOO_SHORT");
        m_db.Exec("UPDATE channels SET sequence=?,candidate=?,phase='canary',policy_epoch=?,not_before=?,"
        "update_id=?,runtime_observed='' WHERE name=?",
        {
            std::to_string(seq),capsule,std::to_string(p.epoch),std::to_string(static_cast<uint64_t>(now)+p.canary_ms),
            update_id,name
        });
        m_db.Exec("DELETE FROM observations WHERE channel=?", {
            name
        });
        m_db.Event("channel-staged",capsule,Object());
        tx.Commit();
    }
    void Lifecycle::Observe(const std::string& name,const std::string& receipt_id,int64_t now) {
        auto p=Policy::Load(m_db,now);
        auto receipt=m_db.Get(receipt_id);
        Require(Text(receipt,"kind")=="receipt","SEC_CANARY_RECEIPT");
        auto signers=p.Check(receipt,"worker",m_db,now);
        Require(signers.size()==1,"SEC_CANARY_SIGNER");
        const auto local=ReadLocalConfig(m_db);
        const auto& signer=p.Find(signers[0],"worker",m_db,now);
        Require(signer.host==Text(local,"host",128),"SEC_CANARY_NOT_LOCAL");
        const auto& r=receipt["body"];
        Current(r,p,now);
        Require(Text(r,"host",128)==signer.host&&Boolean(r,"dispatched")&&Text(r,"outcome")=="PASS",
        "SEC_CANARY_NOT_EXECUTED");
        Database::Transaction tx(m_db);
        auto rows=m_db.Query("SELECT candidate,update_id,not_before,phase,mandate_id FROM channels WHERE name=?",
        {
            name
        });
        Require(rows.size()==1&&rows[0][3]=="canary","SEC_NO_CANARY");
        const auto& row=rows[0];
        auto a=AdmitCapsule(m_db,p,row[0],now);
        if(m_db.Meta("mesh_required","0")=="1")MeshRequireLive(m_db,p,row[0],now);
        CheckMandate(p,m_db.Get(row[4]),a,now);
        Require(DigestField(r,"composition")==a.composition_id&&DigestField(r,"runtime")==a.runtime&&
        DigestField(r,"request")==row[1],"SEC_CANARY_GENERATION");
        const auto& runtime=local["runtimes"][a.runtime];
        Require(DigestField(r,"package")==DigestField(runtime,"canary_package"),"SEC_CANARY_PACKAGE");
        const auto& plan=local["evaluation_plans"][DigestField(runtime,"canary_package")]["plan"];
        Require(PlanId(plan)==DigestField(runtime,"canary_package")&&
        DigestField(r,"sandbox")==DigestField(plan,"sandbox")&&
        DigestField(r,"output_digest")==DigestField(plan,"expected_output_sha384")&&
        UInt(r,"output_bytes")==UInt(plan,"expected_output_bytes"),"SEC_CANARY_OUTCOME");
        const auto issued=UInt(r,"issued_ms",INT64_MAX),start=ParseUInt(row[2])-p.canary_ms;
        Require(issued>=start&&!m_db.Revoked(receipt_id,now),"SEC_CANARY_STALE");
        m_db.Exec("INSERT OR IGNORE INTO observations(channel,capsule,receipt,at_ms) VALUES(?,?,?,?)",
        {
            name,row[0],receipt_id,std::to_string(issued)
        });
        m_db.Event("canary-observed",receipt_id,Object());
        tx.Commit();
    }
    void Lifecycle::Activate(const std::string& name,int64_t now) {
        auto p=Policy::Load(m_db,now);
        Database::Transaction tx(m_db);
        m_db.CheckClock(now);
        auto rows=m_db.Query("SELECT candidate,update_id,not_before,phase,mandate_id,active FROM channels WHERE name=?",
        {
            name
        });
        Require(rows.size()==1&&rows[0][3]=="canary","SEC_NO_CANARY");
        const auto& row=rows[0];
        Require(ParseUInt(row[2])<=static_cast<uint64_t>(now),"SEC_CANARY_DURATION");
        auto a=AdmitCapsule(m_db,p,row[0],now);
        if(m_db.Meta("mesh_required","0")=="1")MeshRequireLive(m_db,p,row[0],now);
        CheckMandate(p,m_db.Get(row[4]),a,now);
        auto update=m_db.Get(row[1]);
        p.Check(update,"release",m_db,now,p.release_threshold);
        Current(update["body"],p,now);
        Require(!m_db.Revoked(row[1],now),"SEC_UPDATE_REVOKED");
        auto observations=m_db.Query("SELECT receipt,at_ms FROM observations WHERE channel=? AND capsule=? ORDER BY at_ms",
        {
            name,row[0]
        });
        Require(observations.size()>=2,"SEC_CANARY_SAMPLES");
        uint64_t first=UINT64_MAX,last=0;
        for(const auto& observed:observations) {
            auto receipt=m_db.Get(observed[0]);
            p.Check(receipt,"worker",m_db,now);
            Current(receipt["body"],p,now);
            Require(!m_db.Revoked(observed[0],now)&&DigestField(receipt["body"],"request")==row[1],"SEC_CANARY_REVOKED");
            const auto at=ParseUInt(observed[1]);
            first=std::min(first,at);
            last=std::max(last,at);
        }
        Require(last>=ParseUInt(row[2])&&last-first>=p.canary_ms,"SEC_CANARY_DURATION");
        (void)VerifyResident(m_db,a.composition_id);
        // This is a durable host-selected model binding, not a remote forced update.
        // Every dispatcher resolves this binding and checks its generation again.
        m_db.Exec("UPDATE channels SET previous=active,active=candidate,candidate='',phase='active',runtime_observed=? WHERE name=?",
        {
            a.runtime,name
        });
        m_db.Exec("UPDATE permits SET phase='revoked' WHERE phase='prepared'");
        m_db.Event("channel-activated",row[0],Object());
        tx.Commit();
    }
    void Lifecycle::Tick(int64_t now) {
        auto p=Policy::Load(m_db,now);
        for(const auto& row:m_db.Query("SELECT name,active,previous,candidate,phase,mandate_id FROM channels ORDER BY name LIMIT 128")) {
            const auto name=row[0];
            bool owner_current=false;
            try {
                auto m=m_db.Get(row[5]);
                p.Check(m,"owner",m_db,now);
                Current(m["body"],p,now);
                owner_current=!m_db.Revoked(row[5],now)&&Boolean(m["body"],"automatic_follow");
            }
            catch(...) {
            }
            if(!owner_current||(!row[1].empty()&&!Eligible(p,row[1],now))) {
                bool rollback=false;
                if(owner_current&&!row[2].empty()) {
                    try {
                        auto a=AdmitCapsule(m_db,p,row[2],now);
                        CheckMandate(p,m_db.Get(row[5]),a,now);
                        (void)VerifyResident(m_db,a.composition_id);
                        rollback=true;
                    }
                    catch(...) {
                    }
                }
                Database::Transaction tx(m_db);
                if(rollback)m_db.Exec("UPDATE channels SET active=previous,previous='',candidate='',phase='active' WHERE name=?",
                {
                    name
                });
                else m_db.Exec("UPDATE channels SET candidate='',phase='frozen' WHERE name=?", {
                    name
                });
                m_db.Exec("UPDATE permits SET phase='revoked' WHERE phase='prepared'");
                m_db.Event(rollback?"channel-rolled-back":"channel-frozen",name,Object());
                tx.Commit();
                continue;
            }
            if(row[4]=="canary") {
                if(!Eligible(p,row[3],now)) {
                    Database::Transaction tx(m_db);
                    m_db.Exec("UPDATE channels SET candidate='',phase=? WHERE name=?", {
                        row[1].empty()?"frozen":"active",name
                    });
                    m_db.Event("candidate-quarantined",row[3],Object());
                    tx.Commit();
                }
                else {
                    try {
                        Activate(name,now);
                    }
                    catch(const Error&) {
                        /* Pending evidence remains pending. */
                    }
                }
            }
            // Process signed updates in sequence; a missing predecessor is not skipped.
            std::vector<std::pair<uint64_t,std::string>> updates;
            for(const auto& id:m_db.List("channel",1024)) {
                auto e=m_db.Get(id);
                if(e["body"]["name"].isStr()&&e["body"]["name"].get_str()==name)
                updates.emplace_back(UInt(e["body"],"sequence",INT64_MAX),id);
            }
            std::sort(updates.begin(),updates.end());
            for(const auto& [sequence,id]:updates) {
                const auto current=m_db.Query("SELECT sequence,update_id FROM channels WHERE name=?", {
                    name
                });
                if(current.empty())break;
                const auto existing=ParseUInt(current[0][0]);
                // Skip already accepted history without rehashing a multi-gigabyte
                // resident model every two seconds. A conflicting current sequence
                // still reaches Stage and freezes the channel.
                if(sequence<existing || (sequence==existing&&id==current[0][1]))continue;
                try {
                    Stage(id,now);
                }
                catch(const Error&) {
                    /* No fallback to unqualified activation. */
                }
            }
        }
    }
    Json Lifecycle::Status() {
        Json out=Array();
        for(const auto& r:m_db.Query("SELECT name,sequence,active,previous,candidate,phase,policy_epoch,not_before FROM channels ORDER BY name LIMIT 128")) {
            Json row=Object();
            row.pushKV("name",r[0]);
            row.pushKV("sequence",ParseUInt(r[1]));
            row.pushKV("active_capsule",r[2]);
            row.pushKV("previous_capsule",r[3]);
            row.pushKV("candidate_capsule",r[4]);
            row.pushKV("phase",r[5]);
            row.pushKV("policy_epoch",ParseUInt(r[6]));
            row.pushKV("not_before_ms",ParseUInt(r[7]));
            row.pushKV("privilege_escalation",false);
            out.push_back(row);
        }
        return out;
    }
}
// namespace modelnet::security

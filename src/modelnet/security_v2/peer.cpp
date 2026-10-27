// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/peer.h>
#include <algorithm>
#include <set>
namespace modelnet::security {
    namespace {
        void Tables(Database& db) {
            db.Exec("CREATE TABLE IF NOT EXISTS peer_pending(id TEXT PRIMARY KEY,peer TEXT NOT NULL,expires INTEGER NOT NULL) WITHOUT ROWID");
            db.Exec("CREATE TABLE IF NOT EXISTS peer_wants(peer TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(peer,id)) WITHOUT ROWID");
        }
        bool ExportKind(const std::string& kind) {
            static const std::set<std::string> allowed {
                "composition","capsule","evaluation","receipt","challenge","channel","revocation","anchor"
            };
            return allowed.contains(kind);
        }
        std::string CheckPacket(Database& db,const Policy& p,const Json& e,const std::string& pin,
        std::string_view phase,const std::string& self,int64_t now) {
            Require(Canonical(e).size()<=MAX_PEER_BYTES,"SEC_PEER_LIMIT");
            ValidateEnvelope(e);
            Require(Text(e,"kind")=="peer"&&e["signatures"].size()==1,"SEC_PEER_SIGNATURE");
            const auto& b=e["body"];
            const auto sender=DigestField(b,"sender");
            // Cheap enrolled-key/pin/role checks precede costly PQ verification.
            const auto& principal=p.Find(sender,"peer",db,now);
            Require(!principal.transport_pin.empty()&&principal.transport_pin==pin,"SEC_PEER_TRANSPORT_PIN");
            Require(KeyId(Unhex(Text(e["signatures"][0],"public_key",PK_BYTES*2),PK_BYTES))==sender,
            "SEC_PEER_SIGNER_BINDING");
            Require(Text(b,"phase")==phase&&DigestField(b,"recipient")==self&&
            DigestField(b,"realm")==p.realm&&UInt(b,"policy_epoch")==p.epoch,"SEC_PEER_AUDIENCE");
            const auto issued=UInt(b,"issued_ms",INT64_MAX),expires=UInt(b,"expires_ms",INT64_MAX);
            Require(issued<=static_cast<uint64_t>(now)&&expires>static_cast<uint64_t>(now)&&
            expires>issued&&expires-issued<=30000,"SEC_PEER_FRESHNESS");
            const auto nonce=Text(b,"nonce",64);
            Require(Unhex(nonce,32).size()==32,"SEC_PEER_NONCE");
            {
                Database::Transaction tx(db);
                db.CheckClock(now);
                auto rates=db.Query("SELECT window,count FROM rates WHERE principal=?", {
                    sender
                });
                const uint64_t window=static_cast<uint64_t>(now)/60000;
                const uint64_t used=rates.empty()||ParseUInt(rates[0][0])!=window?0:ParseUInt(rates[0][1]);
                Require(used<60,"SEC_PEER_RATE");
                db.Exec("INSERT INTO rates(principal,window,count) VALUES(?,?,?) ON CONFLICT(principal) DO UPDATE SET window=excluded.window,count=excluded.count",
                {
                    sender,std::to_string(window),std::to_string(used+1)
                });
                tx.Commit();
            }
            p.Check(e,"peer",db,now);
            Database::Transaction tx(db);
            db.Exec("DELETE FROM peer_nonces WHERE expires<=?", {
                std::to_string(now)
            });
            Require(db.Query("SELECT nonce FROM peer_nonces WHERE principal=? AND nonce=?", {
                sender,nonce
            }).empty(),"SEC_PEER_REPLAY");
            Require(ParseUInt(db.Query("SELECT count(*) FROM peer_nonces")[0][0])<8192,"SEC_PEER_NONCE_QUOTA");
            db.Exec("INSERT INTO peer_nonces(principal,nonce,expires) VALUES(?,?,?)", {
                sender,nonce,std::to_string(expires)
            });
            tx.Commit();
            return sender;
        }
        Json Header(const Policy& p,const std::string& self,const std::string& recipient,std::string_view phase,
        int64_t now) {
            Json b=Object();
            b.pushKV("realm",p.realm);
            b.pushKV("policy_epoch",p.epoch);
            b.pushKV("sender",self);
            b.pushKV("recipient",recipient);
            b.pushKV("phase",std::string(phase));
            b.pushKV("nonce",Hex(RandomBytes(32)));
            b.pushKV("issued_ms",now);
            b.pushKV("expires_ms",now+30000);
            return b;
        }
        void Want(Database& db,const std::string& peer,const std::string& id) {
            if(!IsHash(id)||db.Has(id))return;
            auto count=db.Query("SELECT count(*) FROM peer_wants WHERE peer=?", {
                peer
            });
            if(ParseUInt(count[0][0])<1024)db.Exec("INSERT OR IGNORE INTO peer_wants(peer,id) VALUES(?,?)", {
                peer,id
            });
        }
    }
    std::vector<std::string> RecordDependencies(const Json& e) {
        std::set<std::string> refs;
        const auto kind=Text(e,"kind");
        const auto& b=e["body"];
        for(auto field: {
            "composition","capsule","execution_receipt","challenge"
        })
        if(b[field].isStr()&&IsHash(b[field].get_str()))refs.insert(b[field].get_str());
        if(kind=="capsule")for(const auto& x:StringArray(b["evaluations"],256))refs.insert(x);
        if(kind=="composition")for(const auto& x:StringArray(b["parents"],32))refs.insert(x);
        return {
            refs.begin(),refs.end()
        };
    }
    void PublishEvidenceClosure(Database& db,const std::string& root,int64_t now) {
        auto p=Policy::Load(db,now);
        std::set<std::string> seen;
        std::vector<std::string> queue {
            root
        };
        bool has_public_composition=false;
        for(size_t i=0; i<queue.size(); ++i) {
            Require(queue.size()<=512,"SEC_PUBLICATION_CLOSURE_LIMIT");
            const auto id=queue[i];
            if(!seen.insert(id).second)continue;
            const auto e=db.Get(id);
            const auto kind=Text(e,"kind");
            Require(ExportKind(kind),"SEC_PRIVATE_KIND");
            if(kind=="composition") {
                Require(Text(e["body"],"visibility")=="public","SEC_PRIVATE_COMPOSITION");
                p.Check(e,"publisher",db,now);
                has_public_composition=true;
            }
            for(const auto& dependency:RecordDependencies(e))queue.push_back(dependency);
        }
        Require(has_public_composition,"SEC_NO_PUBLIC_SUBJECT");
        Database::Transaction tx(db);
        for(const auto& id:seen)db.Exec("UPDATE objects SET visibility='public' WHERE id=?", {
            id
        });
        db.Event("evidence-published",root,Object());
        tx.Commit();
    }
    Json MakePeerRequest(Database& db,const std::string& peer,int64_t now) {
        Tables(db);
        auto p=Policy::Load(db,now);
        auto key=LoadLocalIdentity(db,p,"peer",now);
        const auto self=KeyId(key.public_key);
        Require(peer!=self,"SEC_PEER_SELF");
        p.Find(peer,"peer",db,now);
        auto b=Header(p,self,peer,"request",now);
        auto cursors=db.Query("SELECT cursor FROM peer_cursor WHERE peer=?", {
            peer
        });
        b.pushKV("cursor",cursors.empty()?"":cursors[0][0]);
        Json want=Array();
        for(const auto& r:db.Query("SELECT id FROM peer_wants WHERE peer=? ORDER BY id LIMIT 8", {
            peer
        }))want.push_back(r[0]);
        b.pushKV("want",want);
        auto e=Envelope("peer",b);
        AddSignature(e,key);
        Database::Transaction tx(db);
        db.Exec("DELETE FROM peer_pending WHERE expires<=?", {
            std::to_string(now)
        });
        Require(ParseUInt(db.Query("SELECT count(*) FROM peer_pending")[0][0])<128,"SEC_PEER_OUTSTANDING");
        db.Exec("INSERT INTO peer_pending(id,peer,expires) VALUES(?,?,?)", {
            RecordId(e),peer,std::to_string(now+30000)
        });
        tx.Commit();
        return e;
    }
    Json HandlePeerRequest(Database& db,const Json& e,const std::string& pin,int64_t now) {
        Tables(db);
        auto p=Policy::Load(db,now);
        auto key=LoadLocalIdentity(db,p,"peer",now);
        const auto self=KeyId(key.public_key);
        const auto& b=e["body"];
        Fields(b, {
            "realm","policy_epoch","sender","recipient","phase","nonce","issued_ms","expires_ms","cursor","want"
        });
        auto peer=CheckPacket(db,p,e,pin,"request",self,now);
        Require(b["cursor"].isStr()&&(b["cursor"].get_str().empty()||IsHash(b["cursor"].get_str())),"SEC_PEER_CURSOR");
        auto want=StringArray(b["want"],8);
        for(const auto& id:want)Require(IsHash(id),"SEC_PEER_WANT");
        Json response=Header(p,self,peer,"response",now);
        response.pushKV("request_id",RecordId(e));
        Json records=Array(),missing=Array(),inventory=Array();
        size_t bytes=0;
        for(const auto& id:want) {
            auto rows=db.Query("SELECT envelope FROM objects WHERE id=? AND visibility='public'", {
                id
            });
            if(rows.empty()||!ExportKind(Text(Parse(rows[0][0]),"kind"))||bytes+rows[0][0].size()>192*1024) {
                missing.push_back(id);
                continue;
            }
            bytes+=rows[0][0].size();
            records.push_back(Parse(rows[0][0]));
        }
        auto rows=db.Query("SELECT id FROM objects WHERE visibility='public' AND id>? ORDER BY id LIMIT 17",
        {
            b["cursor"].get_str()
        });
        for(size_t i=0; i<std::min<size_t>(16,rows.size()); ++i)inventory.push_back(rows[i][0]);
        response.pushKV("inventory",inventory);
        response.pushKV("next_cursor",rows.size()>16?rows[15][0]:"");
        response.pushKV("records",records);
        response.pushKV("not_available",missing);
        auto out=Envelope("peer",response);
        AddSignature(out,key);
        Require(Canonical(out).size()<=MAX_PEER_BYTES,"SEC_PEER_LIMIT");
        return out;
    }
    void AcceptPeerResponse(Database& db,const Json& e,const std::string& pin,int64_t now) {
        Tables(db);
        auto p=Policy::Load(db,now);
        auto key=LoadLocalIdentity(db,p,"peer",now);
        const auto self=KeyId(key.public_key);
        const auto& b=e["body"];
        Fields(b, {
            "realm","policy_epoch","sender","recipient","phase","nonce","issued_ms","expires_ms", "request_id","inventory",
            "next_cursor","records","not_available"
        });
        const auto peer=CheckPacket(db,p,e,pin,"response",self,now);
        const auto request_id=DigestField(b,"request_id");
        {
            Database::Transaction tx(db);
            auto rows=db.Query("SELECT peer,expires FROM peer_pending WHERE id=?", {
                request_id
            });
            Require(rows.size()==1&&rows[0][0]==peer&&ParseUInt(rows[0][1])>static_cast<uint64_t>(now),"SEC_UNSOLICITED_RESPONSE");
            db.Exec("DELETE FROM peer_pending WHERE id=?", {
                request_id
            });
            tx.Commit();
        }
        Require(b["records"].isArray()&&b["records"].size()<=8,"SEC_PEER_RECORD_COUNT");
        for(const auto& record:b["records"].getValues()) {
            Require(ExportKind(Text(record,"kind")),"SEC_PEER_PRIVATE_RECORD");
            const auto id=RecordId(record);
            Require(!db.Query("SELECT id FROM peer_wants WHERE peer=? AND id=?", {
                peer,id
            }).empty(),"SEC_UNREQUESTED_RECORD");
            ImportRecord(db,p,record,now,true);
            Database::Transaction tx(db);
            db.Exec("DELETE FROM peer_wants WHERE peer=? AND id=?", {
                peer,id
            });
            for(const auto& dependency:RecordDependencies(record))Want(db,peer,dependency);
            tx.Commit();
        }
        Database::Transaction tx(db);
        for(const auto& id:StringArray(b["inventory"],16)) {
            Require(IsHash(id),"SEC_PEER_INVENTORY");
            Want(db,peer,id);
        }
        for(const auto& id:StringArray(b["not_available"],8))db.Exec("DELETE FROM peer_wants WHERE peer=? AND id=?",
        {
            peer,id
        });
        Require(b["next_cursor"].isStr()&&(b["next_cursor"].get_str().empty()||IsHash(b["next_cursor"].get_str())),
        "SEC_PEER_CURSOR");
        db.Exec("INSERT INTO peer_cursor(peer,cursor) VALUES(?,?) ON CONFLICT(peer) DO UPDATE SET cursor=excluded.cursor",
        {
            peer,b["next_cursor"].get_str()
        });
        db.Event("peer-evidence-synchronized",peer,Object());
        tx.Commit();
    }
}
// namespace modelnet::security

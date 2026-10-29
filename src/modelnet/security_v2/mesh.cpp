// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/mesh.h>
#include <algorithm>
#include <limits>
#include <map>
#include <set>
namespace modelnet::security {
namespace {
constexpr uint64_t kPacketLease=30000, kMaxPeerAge=30000, kRejectedMs=86400000;
constexpr size_t kMaxObjects=16, kMaxWants=8, kMaxRejected=4096;
const std::set<std::string> kExportKinds{"composition","capsule","evaluation","receipt","challenge","channel","revocation","campaign","anchor","work","result"};
void Ensure(bool condition,const char* error){Require(condition,error);}
Json Header(const Policy& p,const std::string& self,const std::string& peer,std::string_view phase,int64_t now){
    Json b=Object();b.pushKV("realm",p.realm);b.pushKV("policy_epoch",p.epoch);b.pushKV("sender",self);
    b.pushKV("recipient",peer);b.pushKV("phase",std::string(phase));b.pushKV("nonce",Hex(RandomBytes(32)));
    b.pushKV("issued_ms",now);b.pushKV("expires_ms",now+static_cast<int64_t>(kPacketLease));return b;
}
void CheckOuter(const Json& packet,size_t cap){Ensure(Canonical(packet).size()<=cap,"SEC_MESH_PACKET_LIMIT");ValidateEnvelope(packet);
    Ensure(Text(packet,"kind")=="mesh"&&packet["signatures"].size()==1,"SEC_MESH_PACKET_KIND");}
std::string Check(Database& db,const Policy& p,const Json& packet,const std::string& pin,
                  const std::string& expected_phase,const std::string& recipient,int64_t now){
    CheckOuter(packet,MAX_MESH_PACKET);
    const auto& b=packet["body"];const auto sender=DigestField(b,"sender");
    const auto& principal=p.Find(sender,"peer",db,now);
    Ensure(!principal.transport_pin.empty()&&principal.transport_pin==pin,"SEC_MESH_PIN");
    const auto raw=Unhex(Text(packet["signatures"][0],"public_key",PK_BYTES*2),PK_BYTES);
    Ensure(KeyId(raw)==sender,"SEC_MESH_SENDER");
    Ensure(Text(b,"phase")==expected_phase&&DigestField(b,"recipient")==recipient&&
           DigestField(b,"realm")==p.realm&&UInt(b,"policy_epoch")==p.epoch,"SEC_MESH_AUDIENCE");
    const auto issued=UInt(b,"issued_ms",INT64_MAX),expiry=UInt(b,"expires_ms",INT64_MAX);
    Ensure(issued<=static_cast<uint64_t>(now)&&expiry>static_cast<uint64_t>(now)&&
           expiry-issued<=kPacketLease,"SEC_MESH_TIME");
    const auto nonce=Text(b,"nonce",64);Unhex(nonce,32);
    p.Check(packet,"peer",db,now);
    Database::Transaction tx(db);db.CheckClock(now);
    db.Exec("DELETE FROM mesh_nonces WHERE expires<=?",{std::to_string(now)});
    Ensure(db.Query("SELECT nonce FROM mesh_nonces WHERE peer=? AND nonce=?",{sender,nonce}).empty(),"SEC_MESH_REPLAY");
    auto count=db.Query("SELECT COUNT(*) FROM mesh_nonces");
    Ensure(ParseUInt(count[0][0])<8192,"SEC_MESH_NONCE_LIMIT");
    const uint64_t minute=static_cast<uint64_t>(now)/60000;
    auto rates=db.Query("SELECT minute,n FROM mesh_rates WHERE peer=?",{sender});
    const uint64_t n=rates.empty()||ParseUInt(rates[0][0])!=minute?0:ParseUInt(rates[0][1]);
    Ensure(n<60,"SEC_MESH_RATE");
    db.Exec("INSERT INTO mesh_rates(peer,minute,n) VALUES(?,?,?) ON CONFLICT(peer) DO UPDATE SET minute=excluded.minute,n=excluded.n",
            {sender,std::to_string(minute),std::to_string(n+1)});
    db.Exec("INSERT INTO mesh_nonces(peer,nonce,expires) VALUES(?,?,?)",{sender,nonce,std::to_string(expiry)});
    db.Exec("INSERT INTO mesh_live(peer,seen_ms,domain,host,epoch) VALUES(?,?,?,?,?) "
            "ON CONFLICT(peer) DO UPDATE SET seen_ms=excluded.seen_ms,domain=excluded.domain,host=excluded.host,epoch=excluded.epoch",
            {sender,std::to_string(now),principal.domain,principal.host,std::to_string(p.epoch)});
    tx.Commit();return sender;
}
void Want(Database& db,const std::string& peer,const std::string& id){
    if(!IsHash(id)||db.Has(id))return;
    if(!db.Query("SELECT id FROM mesh_rejected WHERE peer=? AND id=?",{peer,id}).empty())return;
    const auto rows=db.Query("SELECT count(*) FROM mesh_wants WHERE peer=?",{peer});
    if(ParseUInt(rows[0][0])<512)db.Exec("INSERT OR IGNORE INTO mesh_wants(peer,id) VALUES(?,?)",{peer,id});
}
void ExportOne(Database& db,const std::string& id,int64_t now){
    const auto record=db.Get(id);const auto kind=Text(record,"kind");
    Ensure(kExportKinds.contains(kind),"SEC_MESH_PRIVATE_KIND");
    auto p=Policy::Load(db,now);
    if(kind=="composition"){
        if(Text(record["body"],"visibility")=="private") {
            const auto local=ReadLocalConfig(db);
            const auto& settings=local["continuous_security"];
            Ensure(settings.isObject()&&settings["allow_private_evidence"].isBool()&&
                   settings["allow_private_evidence"].get_bool(),"SEC_MESH_PRIVATE_COMPOSITION");
        }
        p.Check(record,"publisher",db,now);
    }
    if(kind=="campaign")p.Check(record,"owner",db,now);
    if(kind=="work")p.Check(record,"coordinator",db,now);
    db.Exec("INSERT OR IGNORE INTO mesh_outbox(id,kind) VALUES(?,?)",{id,kind});
}
void ExportClosure(Database& db,const std::string& id,int64_t now){
    std::vector<std::string> todo{id};std::set<std::string> visited;
    for(size_t i=0;i<todo.size();++i){
        Ensure(todo.size()<=256,"SEC_MESH_CLOSURE_LIMIT");
        if(!visited.insert(todo[i]).second)continue;
        auto e=db.Get(todo[i]);ExportOne(db,todo[i],now);
        for(const auto& child:RecordDependencies(e)){
            if(db.Has(child)){
                auto ref=db.Get(child);
                if(kExportKinds.contains(Text(ref,"kind")))todo.push_back(child);
            }
        }
    }
}
bool ApprovedCampaign(Database& db,const std::string& campaign){
    if(!IsHash(campaign))return false;
    auto local=ReadLocalConfig(db);const auto& security=local["continuous_security"];
    if(!security.isObject()||!security["enabled"].isBool()||!security["enabled"].get_bool())return false;
    auto allow=StringArray(security["allowed_campaigns"],128);
    return std::find(allow.begin(),allow.end(),campaign)!=allow.end();
}
// Policy::Check for stored records: a signer revoked or no longer enrolled for
// the role gives an empty list instead of a throw.
std::vector<std::string> CurrentSigners(Database& db,const Policy& p,const Json& e,std::string_view role,int64_t now){
    try{return p.Check(e,role,db,now);}
    catch(const Error& error){
        if(error.code!="SEC_SIGNER_REVOKED"&&error.code!="SEC_SIGNATURE_THRESHOLD")throw;
        return {};
    }
}
uint64_t MaxAge(Database& db){
    auto local=ReadLocalConfig(db);const auto& settings=local["continuous_security"];
    if(!settings.isObject())return 0;
    return UInt(settings,"max_evidence_age_ms",7ull*86400000);
}
void VerifyReport(Database& db,const Policy& p,const Json& challenge,const Json& report,
                  const std::string& composition,int64_t now,std::set<std::string>& domains,
                  std::set<std::string>& hosts,std::set<std::string>& signers){
    Ensure(Text(report,"kind")=="evaluation","SEC_MESH_EVAL_KIND");
    const auto& r=report["body"];const auto& ch=challenge["body"];
    if(Text(r,"outcome")!="PASS")throw Error("SEC_MESH_NEGATIVE_REPORT");
    Ensure(DigestField(r,"composition")==composition&&DigestField(r,"challenge")==RecordId(challenge)&&
           DigestField(r,"campaign")==DigestField(ch,"campaign")&&
           DigestField(r,"suite")==DigestField(ch,"suite")&&
           DigestField(r,"sample_commitment")==DigestField(ch,"sample_commitment")&&
           Text(r,"gate")==Text(ch,"gate"),"SEC_MESH_REPORT_BIND");
    const auto at=UInt(r,"issued_ms",INT64_MAX);
    Ensure(at>=UInt(ch,"issued_ms",INT64_MAX)&&at<UInt(ch,"expires_ms",INT64_MAX)&&
           at<=static_cast<uint64_t>(now)&&static_cast<uint64_t>(now)-at<=MaxAge(db),"SEC_MESH_REPORT_AGE");
    const auto matched=p.Check(report,"evaluator",db,now);
    Ensure(matched.size()==1,"SEC_MESH_REPORT_SIGNER");const auto& signer=matched[0];
    const auto& principal=p.Find(signer,"worker",db,now);
    Ensure(Text(r,"host")==principal.host&&Text(r,"physical_host_evidence")==principal.host,"SEC_MESH_HOST");
    auto receipt=db.Get(DigestField(r,"execution_receipt"));
    Ensure(Text(receipt,"kind")=="receipt","SEC_MESH_RECEIPT_KIND");
    auto workers=p.Check(receipt,"worker",db,now);
    Ensure(workers.size()==1&&workers[0]==signer,"SEC_MESH_RECEIPT_SIGNER");
    const auto& rb=receipt["body"];
    Ensure(Boolean(rb,"dispatched")&&Text(rb,"outcome")=="PASS"&&
           DigestField(rb,"request")==RecordId(challenge)&&
           DigestField(rb,"composition")==composition&&
           DigestField(rb,"package")==DigestField(ch,"package")&&
           DigestField(rb,"runtime")==DigestField(r,"runtime")&&
           DigestField(rb,"sandbox")==DigestField(r,"sandbox")&&
           DigestField(rb,"output_digest")==DigestField(r,"output_digest")&&
           Text(rb,"host")==principal.host,"SEC_MESH_RECEIPT_BIND");
    Ensure(!db.Revoked(RecordId(report),now)&&!db.Revoked(RecordId(receipt),now),"SEC_MESH_REVOKED");
    if(!signers.insert(signer).second)throw Error("SEC_MESH_DUPLICATE_EVALUATOR");
    domains.insert(principal.domain);hosts.insert(principal.host);
    const auto local=ReadLocalConfig(db);const auto own_host=Text(local,"host",128);
    if(principal.host==own_host){
        Ensure(db.Meta("runtime_available","0")=="1","SEC_MESH_LOCAL_OFFLINE");
    }else{
        auto last=db.Query("SELECT seen_ms,epoch FROM mesh_live WHERE peer=?",{signer});
        Ensure(last.size()==1&&ParseUInt(last[0][1])==p.epoch&&
               ParseUInt(last[0][0])<=static_cast<uint64_t>(now)&&
               static_cast<uint64_t>(now)-ParseUInt(last[0][0])<=kMaxPeerAge,"SEC_MESH_PEER_OFFLINE");
    }
}
} // namespace

void MeshTables(Database& db){
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_nonces(peer TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(peer,nonce)) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_rates(peer TEXT PRIMARY KEY,minute INTEGER NOT NULL,n INTEGER NOT NULL) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_outbox(id TEXT PRIMARY KEY,kind TEXT NOT NULL) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_wants(peer TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(peer,id)) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_pending(id TEXT PRIMARY KEY,peer TEXT NOT NULL,expires INTEGER NOT NULL) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_cursors(peer TEXT PRIMARY KEY,cursor TEXT NOT NULL) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_rejected(peer TEXT NOT NULL,id TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(peer,id)) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_live(peer TEXT PRIMARY KEY,seen_ms INTEGER NOT NULL,domain TEXT NOT NULL,host TEXT NOT NULL,epoch INTEGER NOT NULL) WITHOUT ROWID");
    db.Exec("CREATE TABLE IF NOT EXISTS mesh_rounds(campaign TEXT NOT NULL,round INTEGER NOT NULL,challenge TEXT NOT NULL,PRIMARY KEY(campaign,round)) WITHOUT ROWID");
}
void MeshExport(Database& db,const std::string& id,int64_t now){
    MeshTables(db);(void)Policy::Load(db,now);
    Database::Transaction tx(db);ExportClosure(db,id,now);db.Event("mesh-export",id,Object());tx.Commit();
}
Json MeshRequest(Database& db,const std::string& peer,int64_t now){
    MeshTables(db);auto p=Policy::Load(db,now);auto key=LoadLocalIdentity(db,p,"peer",now);
    const auto self=KeyId(key.public_key);Ensure(peer!=self,"SEC_MESH_SELF");
    p.Find(peer,"peer",db,now);
    auto b=Header(p,self,peer,"request",now);
    const auto rows=db.Query("SELECT cursor FROM mesh_cursors WHERE peer=?",{peer});
    b.pushKV("cursor",rows.empty()?"":rows[0][0]);Json want=Array();
    for(const auto& row:db.Query("SELECT id FROM mesh_wants WHERE peer=? ORDER BY id LIMIT 8",{peer}))want.push_back(row[0]);
    b.pushKV("want",want);auto packet=Envelope("mesh",b);AddSignature(packet,key);
    Database::Transaction tx(db);db.Exec("DELETE FROM mesh_pending WHERE expires<=?",{std::to_string(now)});
    Ensure(ParseUInt(db.Query("SELECT count(*) FROM mesh_pending")[0][0])<128,"SEC_MESH_PENDING_LIMIT");
    db.Exec("INSERT INTO mesh_pending(id,peer,expires) VALUES(?,?,?)",{RecordId(packet),peer,std::to_string(now+kPacketLease)});
    tx.Commit();return packet;
}
Json MeshHandle(Database& db,const Json& packet,const std::string& pin,int64_t now){
    MeshTables(db);auto p=Policy::Load(db,now);auto key=LoadLocalIdentity(db,p,"peer",now);
    const auto self=KeyId(key.public_key);
    Fields(packet["body"],{"realm","policy_epoch","sender","recipient","phase","nonce","issued_ms","expires_ms","cursor","want"});
    const auto peer=Check(db,p,packet,pin,"request",self,now);const auto& b=packet["body"];
    Ensure(b["cursor"].isStr()&&(b["cursor"].get_str().empty()||IsHash(b["cursor"].get_str())),"SEC_MESH_CURSOR");
    auto requested=StringArray(b["want"],kMaxWants);
    for(const auto& id:requested)Ensure(IsHash(id),"SEC_MESH_WANT");
    Json response=Header(p,self,peer,"response",now);response.pushKV("request_id",RecordId(packet));
    Json records=Array(),inventory=Array();size_t bytes=0;
    for(const auto& id:requested){
        auto rows=db.Query("SELECT o.envelope FROM objects o JOIN mesh_outbox m ON m.id=o.id WHERE o.id=?",{id});
        if(rows.empty()||bytes+rows[0][0].size()>192*1024)continue;
        bytes+=rows[0][0].size();records.push_back(Parse(rows[0][0]));
    }
    auto rows=db.Query("SELECT id FROM mesh_outbox WHERE id>? ORDER BY id LIMIT 17",{b["cursor"].get_str()});
    for(size_t i=0;i<std::min(kMaxObjects,rows.size());++i)inventory.push_back(rows[i][0]);
    response.pushKV("inventory",inventory);response.pushKV("next_cursor",rows.size()>kMaxObjects?rows[kMaxObjects-1][0]:"");
    response.pushKV("records",records);auto result=Envelope("mesh",response);AddSignature(result,key);
    Ensure(Canonical(result).size()<=MAX_MESH_PACKET,"SEC_MESH_PACKET_LIMIT");return result;
}
void MeshAccept(Database& db,const Json& response,const std::string& pin,int64_t now){
    MeshTables(db);auto p=Policy::Load(db,now);auto key=LoadLocalIdentity(db,p,"peer",now);
    const auto self=KeyId(key.public_key);
    Fields(response["body"],{"realm","policy_epoch","sender","recipient","phase","nonce","issued_ms","expires_ms","request_id","inventory","next_cursor","records"});
    const auto peer=Check(db,p,response,pin,"response",self,now);const auto& b=response["body"];
    auto id=DigestField(b,"request_id");auto outstanding=db.Query("SELECT peer,expires FROM mesh_pending WHERE id=?",{id});
    Ensure(outstanding.size()==1&&outstanding[0][0]==peer&&ParseUInt(outstanding[0][1])>static_cast<uint64_t>(now),"SEC_MESH_UNSOLICITED");
    auto inventory=StringArray(b["inventory"],kMaxObjects);
    Ensure(b["next_cursor"].isStr(),"SEC_MESH_CURSOR");
    auto next=b["next_cursor"].get_str();Ensure(next.empty()||IsHash(next),"SEC_MESH_CURSOR");
    Ensure(b["records"].isArray()&&b["records"].size()<=kMaxWants,"SEC_MESH_RECORD_LIMIT");
    db.Exec("DELETE FROM mesh_rejected WHERE expires<=?",{std::to_string(now)});
    for(const auto& item:b["records"].getValues()){
        Ensure(Canonical(item).size()<=MAX_RECORD,"SEC_MESH_RECORD_LIMIT");
        ValidateEnvelope(item);
        const auto kind=Text(item,"kind");Ensure(kExportKinds.contains(kind),"SEC_MESH_PRIVATE_KIND");
        const auto record_id=RecordId(item);
        if(!db.Has(record_id)){
            try{ImportRecord(db,p,item,now,true);}
            catch(const Error& e){
                // Not importable on this node (expired or not yet valid, record or
                // signer revoked, another policy epoch): drop the want, keep syncing,
                // and do not want it from this peer's inventory again for a day.
                if(e.code!="SEC_EXPIRED_OR_FUTURE"&&e.code!="SEC_RECORD_REVOKED"&&
                   e.code!="SEC_SIGNER_REVOKED"&&e.code!="SEC_POLICY_BINDING")throw;
                db.Exec("DELETE FROM mesh_wants WHERE peer=? AND id=?",{peer,record_id});
                if(ParseUInt(db.Query("SELECT count(*) FROM mesh_rejected WHERE peer=?",{peer})[0][0])<kMaxRejected)
                    db.Exec("INSERT OR REPLACE INTO mesh_rejected(peer,id,expires) VALUES(?,?,?)",{peer,record_id,std::to_string(now+static_cast<int64_t>(kRejectedMs))});
                continue;
            }
        }
        for(const auto& dep:RecordDependencies(item))Want(db,peer,dep);
        if(kind=="challenge")Want(db,peer,DigestField(item["body"],"campaign"));
        if(kind=="result"){
            Want(db,peer,DigestField(item["body"],"receipt"));
            Want(db,peer,DigestField(item["body"],"work"));
        }
        db.Exec("DELETE FROM mesh_wants WHERE peer=? AND id=?",{peer,record_id});
    }
    for(const auto& id:inventory){Ensure(IsHash(id),"SEC_MESH_INVENTORY");Want(db,peer,id);}
    Database::Transaction tx(db);
    db.Exec("DELETE FROM mesh_pending WHERE id=?",{id});
    db.Exec("INSERT INTO mesh_cursors(peer,cursor) VALUES(?,?) ON CONFLICT(peer) DO UPDATE SET cursor=excluded.cursor",{peer,next});
    db.Event("mesh-accepted",peer,Object());tx.Commit();
}
void MeshTick(Database& db,int64_t now){
    MeshTables(db);if(!MeshEnabled(db))return;
    auto p=Policy::Load(db,now);auto local=ReadLocalConfig(db);
    const auto allowed=StringArray(local["continuous_security"]["allowed_campaigns"],128);
    if(local["identity"].isObject()){
        const auto id=KeyId(Unhex(Text(local["identity"],"public_key",PK_BYTES*2),PK_BYTES));
        auto self=p.principals.find(id);
        if(self!=p.principals.end()&&self->second.roles.contains("coordinator")){
            for(const auto& campaign:allowed){
                if(!db.Has(campaign))continue;
                auto e=db.Get(campaign);if(Text(e,"kind")!="campaign")continue;
                // A campaign whose owner signer is revoked schedules no more rounds;
                // throwing here would also stop Lifecycle::Tick in Maintain.
                if(CurrentSigners(db,p,e,"owner",now).empty())continue;
                const auto& b=e["body"];
                const auto issued=UInt(b,"issued_ms",INT64_MAX),expires=UInt(b,"expires_ms",INT64_MAX);
                if(static_cast<uint64_t>(now)<issued||static_cast<uint64_t>(now)>=expires)continue;
                const auto interval=UInt(b,"interval_ms",86400000);
                const auto round=(static_cast<uint64_t>(now)-issued)/interval;
                if(round>=UInt(b,"max_rounds",100000))continue;
                if(!db.Query("SELECT challenge FROM mesh_rounds WHERE campaign=? AND round=?",{campaign,std::to_string(round)}).empty())continue;
                auto key=LoadLocalIdentity(db,p,"coordinator",now);
                auto body=Object();body.pushKV("realm",p.realm);body.pushKV("policy_epoch",p.epoch);
                for(auto field:{"composition","suite","sample_commitment","package","gate"})body.pushKV(field,b[field]);
                body.pushKV("campaign",campaign);body.pushKV("trial_limit",p.trial_limit);
                body.pushKV("issued_ms",now);
                const auto expiration=std::min<uint64_t>({expires,static_cast<uint64_t>(now)+p.evidence_ttl_ms,static_cast<uint64_t>(now)+interval});
                Ensure(expiration>static_cast<uint64_t>(now),"SEC_MESH_CAMPAIGN_EXPIRED");
                body.pushKV("expires_ms",expiration);
                auto challenge=Envelope("challenge",body);AddSignature(challenge,key);
                const auto challenge_id=RecordId(challenge);
                // ImportRecord has its own durable transaction; never nest BEGIN.
                ImportRecord(db,p,challenge,now);
                Database::Transaction tx(db);
                db.Exec("INSERT OR IGNORE INTO mesh_rounds(campaign,round,challenge) VALUES(?,?,?)",{campaign,std::to_string(round),challenge_id});
                auto exported=db.Query("SELECT id FROM mesh_outbox WHERE id=?",{campaign});
                if(!exported.empty())ExportOne(db,challenge_id,now);
                tx.Commit();
            }
        }
    }
    // Result publication requires the exact campaign to have been enrolled
    // locally, a real signed local evaluator, and a matching authorized challenge.
    for(const auto& row:db.Query("SELECT envelope FROM objects WHERE kind='evaluation' ORDER BY id LIMIT 1024")){
        auto e=Parse(row[0]);auto b=e["body"];
        if(!b["campaign"].isStr()||!ApprovedCampaign(db,b["campaign"].get_str()))continue;
        auto signers=CurrentSigners(db,p,e,"evaluator",now);
        if(signers.size()!=1)continue;
        const auto host=Text(local,"host",128);
        if(p.Find(signers[0],"evaluator",db,now).host!=host)continue;
        const auto cid=DigestField(b,"challenge");
        if(!db.Has(cid))continue;
        auto challenge=db.Get(cid);
        if(DigestField(challenge["body"],"campaign")!=DigestField(b,"campaign"))continue;
        const auto receipt=DigestField(b,"execution_receipt");
        Database::Transaction tx(db);
        ExportOne(db,RecordId(e),now);ExportOne(db,receipt,now);tx.Commit();
    }
    if(local["remote_work"].isObject()&&local["remote_work"]["enabled"].isBool()&&
       local["remote_work"]["enabled"].get_bool()){
        for(const auto& row:db.Query("SELECT envelope FROM objects WHERE kind='result' ORDER BY id LIMIT 1024")){
            auto result=Parse(row[0]);const auto& b=result["body"];
            const auto work_id=DigestField(b,"work");if(!db.Has(work_id))continue;
            auto work=db.Get(work_id);
            auto signers=CurrentSigners(db,p,result,"worker",now);
            if(signers.size()!=1||p.Find(signers[0],"worker",db,now).host!=Text(local,"host",128))continue;
            if(![&]{auto packages=StringArray(local["remote_work"]["packages"],128);
                return std::find(packages.begin(),packages.end(),DigestField(work["body"],"package"))!=packages.end();}())continue;
            Database::Transaction tx(db);
            ExportOne(db,RecordId(result),now);
            ExportOne(db,DigestField(b,"receipt"),now);
            tx.Commit();
        }
    }
}
bool MeshEnabled(Database& db){
    try {auto local=ReadLocalConfig(db);const auto& s=local["continuous_security"];
        if(!s.isObject())return false;
        Fields(s,{"enabled","max_evidence_age_ms","allowed_campaigns"},{"allow_private_evidence"});
        const auto age=UInt(s,"max_evidence_age_ms",7ull*86400000);
        return Boolean(s,"enabled")&&age>=1000&&age<=300000;
    } catch(...){return false;}
}
void MeshRequireLive(Database& db,const Policy& p,const std::string& capsule,int64_t now){
    MeshTables(db);Ensure(MeshEnabled(db),"SEC_MESH_NOT_ENABLED");
    auto a=AdmitCapsule(db,p,capsule,now);const auto composition=a.composition_id;
    const auto max_age=MaxAge(db);Ensure(max_age>=1000,"SEC_MESH_AGE");
    auto local=ReadLocalConfig(db);const auto allowed=StringArray(local["continuous_security"]["allowed_campaigns"],128);
    std::set<std::string> covered;
    for(const auto& campaign:allowed){
        if(!db.Has(campaign))continue;
        const auto c=db.Get(campaign);if(Text(c,"kind")!="campaign")continue;
        const auto& bc=c["body"];
        if(DigestField(bc,"composition")!=composition)continue;
        p.Check(c,"owner",db,now);
        auto rounds=db.Query("SELECT envelope FROM objects WHERE kind='challenge'");
        Json latest;uint64_t most_recent=0;
        for(const auto& r:rounds){
            auto challenge=Parse(r[0]);const auto& b=challenge["body"];
            if(DigestField(b,"campaign")!=campaign)continue;
            const auto issued=UInt(b,"issued_ms",INT64_MAX);
            if(issued>most_recent){most_recent=issued;latest=challenge;}
        }
        if(!latest.isObject())continue;
        if(most_recent>static_cast<uint64_t>(now)||static_cast<uint64_t>(now)-most_recent>max_age)continue;
        const auto latest_id=RecordId(latest);
        std::set<std::string> domains,hosts,signers;
        for(const auto& r:db.Query("SELECT envelope FROM objects WHERE kind='evaluation'")){
            auto report=Parse(r[0]);const auto& b=report["body"];
            if(DigestField(b,"challenge")!=latest_id)continue;
            VerifyReport(db,p,latest,report,composition,now,domains,hosts,signers);
        }
        if(domains.size()>=p.evaluator_domains&&hosts.size()>=p.physical_hosts)covered.insert(Text(bc,"gate"));
    }
    for(const auto& gate:p.gates)Ensure(covered.contains(gate),"SEC_MESH_INSUFFICIENT_LIVE_COVERAGE");
}
Json MeshStatus(Database& db,int64_t now){
    MeshTables(db);auto out=Object();out.pushKV("schema","BTX/MeshSecurityStatus/v1");
    out.pushKV("enabled",MeshEnabled(db));out.pushKV("qualified_production",false);
    out.pushKV("physical_host_independence_proven",false);
    uint64_t fresh=0;
    for(const auto& row:db.Query("SELECT seen_ms FROM mesh_live")){
        auto at=ParseUInt(row[0]);if(at<=static_cast<uint64_t>(now)&&static_cast<uint64_t>(now)-at<=kMaxPeerAge)++fresh;
    }
    out.pushKV("authenticated_recent_peer_sessions",fresh);
    out.pushKV("enrolled_campaigns",static_cast<uint64_t>(db.Query("SELECT id FROM objects WHERE kind='campaign'").size()));
    out.pushKV("exported_records",ParseUInt(db.Query("SELECT count(*) FROM mesh_outbox")[0][0]));
    out.pushKV("pending_evidence_requests",ParseUInt(db.Query("SELECT count(*) FROM mesh_wants")[0][0]));
    out.pushKV("scope","REALM_SIGNED_EVIDENCE_AND_LOCAL_PINNED_EVALUATOR_EXECUTION");
    return out;
}
} // namespace modelnet::security

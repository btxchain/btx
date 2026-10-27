// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/database.h>
#include <charconv>
#include <set>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace modelnet::security {
    uint64_t ParseUInt(std::string_view s) {
        uint64_t n=0;
        auto r=std::from_chars(s.data(),s.data()+s.size(),n);
        Require(!s.empty()&&r.ec==std::errc()&&r.ptr==s.data()+s.size(),"SEC_DATABASE_INTEGER");
        return n;
    }
    Database::Database(fs::path root):m_root(std::move(root)) {
        EnsurePrivateDirectory(m_root);
        const auto path=m_root/"security.sqlite3";
        std::error_code ec;
        auto st=fs::symlink_status(path,ec);
        Require(!fs::exists(st)||(fs::is_regular_file(st)&&!fs::is_symlink(st)),"SEC_DATABASE_PATH");
        if(!fs::exists(st))WritePrivate(path,"",false);
#ifndef _WIN32
        struct stat metadata {
        };
        Require(lstat(path.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode) &&
        metadata.st_nlink == 1 && metadata.st_uid == geteuid() &&
        (metadata.st_mode & 077) == 0, "SEC_DATABASE_PRIVATE");
#else
        // SQLite's Windows backend opens the path. The parent directory is an
        // owner/SYSTEM-only, non-reparse directory established above.
        Require(fs::file_size(path) <= 512ull*1024*1024, "SEC_DATABASE_LIMIT");
#endif
        const auto u8=path.u8string();
        const std::string filename(u8.begin(),u8.end());
        int flags=SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX;
#ifdef SQLITE_OPEN_NOFOLLOW
        flags|=SQLITE_OPEN_NOFOLLOW;
#endif
        int rc=sqlite3_open_v2(filename.c_str(),&m_db,flags,nullptr);
        if(rc!=SQLITE_OK) {
            if(m_db)sqlite3_close(m_db);
            m_db=nullptr;
            throw Error("SEC_DATABASE_OPEN");
        }
        try {
            sqlite3_busy_timeout(m_db,1500);
            sqlite3_limit(m_db,SQLITE_LIMIT_LENGTH,4*MAX_RECORD);
            sqlite3_limit(m_db,SQLITE_LIMIT_SQL_LENGTH,64*1024);
#ifdef SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION
            sqlite3_db_config(m_db,SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,0,nullptr);
#endif
#ifdef SQLITE_DBCONFIG_DEFENSIVE
            sqlite3_db_config(m_db,SQLITE_DBCONFIG_DEFENSIVE,1,nullptr);
#endif
            Exec("PRAGMA trusted_schema=OFF");
            Exec("PRAGMA foreign_keys=ON");
            Exec("PRAGMA journal_mode=WAL");
            Exec("PRAGMA synchronous=FULL");
            Exec("PRAGMA wal_autocheckpoint=128");
            Exec("PRAGMA max_page_count=131072");
            Exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS objects(id TEXT PRIMARY KEY CHECK(length(id)=96),kind TEXT NOT NULL,envelope TEXT NOT NULL,visibility TEXT NOT NULL CHECK(visibility IN ('public','private')),received INTEGER NOT NULL) WITHOUT ROWID");
            Exec("CREATE INDEX IF NOT EXISTS object_kind ON objects(kind,id)");
            Exec("CREATE TABLE IF NOT EXISTS revoked(subject TEXT PRIMARY KEY,notice TEXT NOT NULL,epoch INTEGER NOT NULL,at_ms INTEGER NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS ancestry(child TEXT NOT NULL,parent TEXT NOT NULL,PRIMARY KEY(child,parent)) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,subject TEXT NOT NULL,payload TEXT NOT NULL,previous TEXT NOT NULL,digest TEXT NOT NULL)");
            Exec("CREATE TABLE IF NOT EXISTS permits(id TEXT PRIMARY KEY,grant_id TEXT NOT NULL,context TEXT NOT NULL,request TEXT NOT NULL,boot TEXT NOT NULL,epoch INTEGER NOT NULL,expires INTEGER NOT NULL,phase TEXT NOT NULL,result TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '') WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS budgets(grant_id TEXT PRIMARY KEY,calls INTEGER NOT NULL,bytes INTEGER NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS channels(name TEXT PRIMARY KEY,sequence INTEGER NOT NULL,active TEXT NOT NULL DEFAULT '',previous TEXT NOT NULL DEFAULT '',candidate TEXT NOT NULL DEFAULT '',phase TEXT NOT NULL,policy_epoch INTEGER NOT NULL,not_before INTEGER NOT NULL DEFAULT 0,update_id TEXT NOT NULL DEFAULT '',mandate_id TEXT NOT NULL DEFAULT '',runtime_observed TEXT NOT NULL DEFAULT '') WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,campaign TEXT NOT NULL,candidate TEXT NOT NULL,claimed_by TEXT NOT NULL DEFAULT '',lease_until INTEGER NOT NULL DEFAULT 0,phase TEXT NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS trials(campaign TEXT NOT NULL,candidate TEXT NOT NULL,PRIMARY KEY(campaign,candidate)) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,grant_id TEXT NOT NULL,phase TEXT NOT NULL,receipt TEXT NOT NULL DEFAULT '',created INTEGER NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS peer_nonces(principal TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(principal,nonce)) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS peer_cursor(peer TEXT PRIMARY KEY,cursor TEXT NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS rates(principal TEXT PRIMARY KEY,window INTEGER NOT NULL,count INTEGER NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY,task TEXT NOT NULL,worker TEXT NOT NULL,expires INTEGER NOT NULL,phase TEXT NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS consumed_controls(id TEXT PRIMARY KEY,at_ms INTEGER NOT NULL) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS observations(channel TEXT NOT NULL,capsule TEXT NOT NULL,receipt TEXT NOT NULL,at_ms INTEGER NOT NULL,PRIMARY KEY(channel,receipt)) WITHOUT ROWID");
            Exec("CREATE TABLE IF NOT EXISTS evaluation_runs(challenge TEXT NOT NULL,evaluator TEXT NOT NULL,phase TEXT NOT NULL,lease_until INTEGER NOT NULL,report TEXT NOT NULL DEFAULT '',PRIMARY KEY(challenge,evaluator)) WITHOUT ROWID");
            if(Meta("schema").empty())SetMeta("schema","1");
            Require(Meta("schema")=="1","SEC_DATABASE_VERSION");
        }
        catch(...) {
            sqlite3_close(m_db);
            m_db=nullptr;
            throw;
        }
    }
    Database::~Database() {
        if(m_db)sqlite3_close(m_db);
    }
    Rows Database::Query(std::string_view sql,const std::vector<std::string>& args) {
        std::lock_guard lock(m_mutex);
        sqlite3_stmt* stmt=nullptr;
        Require(sql.size()<=65536,"SEC_SQL_LIMIT");
        const char* tail=nullptr;
        Require(sqlite3_prepare_v2(m_db,sql.data(),static_cast<int>(sql.size()),&stmt,&tail)==SQLITE_OK,"SEC_DATABASE_PREPARE");
        struct Final {
            sqlite3_stmt* p;
            ~Final() {
                sqlite3_finalize(p);
            }
        }
        finalize {
            stmt
        };
        Require(tail==sql.data()+sql.size()&&sqlite3_bind_parameter_count(stmt)==static_cast<int>(args.size()),
        "SEC_DATABASE_BIND");
        for(size_t i=0; i<args.size(); ++i) {
            Require(args[i].size()<=4*MAX_RECORD,"SEC_DATABASE_VALUE");
            Require(sqlite3_bind_text(stmt,static_cast<int>(i+1),args[i].data(),static_cast<int>(args[i].size()),SQLITE_TRANSIENT)==SQLITE_OK,
            "SEC_DATABASE_BIND");
        }
        Rows out;
        int rc;
        while((rc=sqlite3_step(stmt))==SQLITE_ROW) {
            Require(out.size()<16384,"SEC_DATABASE_ROWS");
            std::vector<std::string> row;
            for(int i=0; i<sqlite3_column_count(stmt); ++i) {
                const auto* p=sqlite3_column_text(stmt,i);
                int n=sqlite3_column_bytes(stmt,i);
                row.emplace_back(p?reinterpret_cast<const char*>(p):"",p?n:0);
            }
            out.push_back(std::move(row));
        }
        Require(rc==SQLITE_DONE,rc==SQLITE_BUSY?"SEC_DATABASE_BUSY":"SEC_DATABASE_WRITE");
        return out;
    }
    void Database::Exec(std::string_view sql,const std::vector<std::string>& args) {
        (void)Query(sql,args);
    }
    Database::Transaction::Transaction(Database& db):m_db(db),m_lock(db.m_mutex) {
        m_db.Exec("BEGIN IMMEDIATE");
    }
    Database::Transaction::~Transaction() {
        if(!m_done)try {
            m_db.Exec("ROLLBACK");
        }
        catch(...) {
        }
    }
    void Database::Transaction::Commit() {
        m_db.Exec("COMMIT");
        m_done=true;
    }
    std::string Database::Meta(const std::string& k,const std::string& fallback) {
        auto r=Query("SELECT v FROM meta WHERE k=?", {
            k
        });
        return r.empty()?fallback:r[0][0];
    }
    void Database::SetMeta(const std::string& k,const std::string& v) {
        Exec("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", {
            k,v
        });
    }
    void Database::CheckClock(int64_t now) {
        Require(now>0,"SEC_CLOCK");
        uint64_t last=ParseUInt(Meta("clock","0"));
        Require(static_cast<uint64_t>(now)>=last,"SEC_CLOCK_ROLLBACK");
        SetMeta("clock",std::to_string(now));
    }
    std::string Database::Put(const Json& e,std::string_view visibility) {
        ValidateEnvelope(e);
        Require(visibility=="public"||visibility=="private","SEC_VISIBILITY");
        auto id=RecordId(e);
        auto existing=Query("SELECT envelope,visibility FROM objects WHERE id=?", {
            id
        });
        Json merged=e;
        if(!existing.empty()) {
            Json old=Parse(existing[0][0]);
            Require(RecordId(old)==id&&Canonical(old["body"])==Canonical(e["body"]),"SEC_OBJECT_CORRUPT");
            std::set<std::string> keys;
            Json sigs=old["signatures"];
            for(const auto& s:sigs.getValues())keys.insert(Text(s,"public_key",PK_BYTES*2));
            for(const auto& s:e["signatures"].getValues())if(keys.insert(Text(s,"public_key",PK_BYTES*2)).second)sigs.push_back(s);
            Require(sigs.size()<=MAX_SIGNATURES,"SEC_SIGNATURE_LIMIT");
            merged=old;
            merged.pushKV("signatures",sigs);
            // Receiving a public duplicate can never publish a locally private object.
            visibility=existing[0][1]=="private"?"private":visibility;
        }
        auto count=Query("SELECT count(*) FROM objects");
        Require(!existing.empty()||ParseUInt(count[0][0])<16384,"SEC_OBJECT_QUOTA");
        Exec("INSERT INTO objects(id,kind,envelope,visibility,received) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET envelope=excluded.envelope,visibility=excluded.visibility",
        {
            id,Text(e,"kind"),Canonical(merged),std::string(visibility),std::to_string(NowMs())
        });
        return id;
    }
    Json Database::Get(const std::string& id) {
        Require(IsHash(id),"SEC_DIGEST");
        auto rows=Query("SELECT envelope FROM objects WHERE id=?", {
            id
        });
        Require(rows.size()==1,"SEC_OBJECT_ABSENT");
        auto e=Parse(rows[0][0]);
        Require(RecordId(e)==id,"SEC_OBJECT_CORRUPT");
        return e;
    }
    bool Database::Has(const std::string& id) {
        return !Query("SELECT id FROM objects WHERE id=?", {
            id
        }).empty();
    }
    std::vector<std::string> Database::List(std::string_view kind,size_t limit,std::string_view after) {
        Require(limit<=1024,"SEC_LIST_LIMIT");
        auto rows=Query("SELECT id FROM objects WHERE kind=? AND id>? ORDER BY id LIMIT ?", {
            std::string(kind),std::string(after),std::to_string(limit)
        });
        std::vector<std::string> ids;
        for(const auto& r:rows)ids.push_back(r[0]);
        return ids;
    }
    void Database::Event(std::string_view kind,std::string_view subject,const Json& payload) {
        Require(kind.size()<=64&&subject.size()<=256,"SEC_EVENT_LIMIT");
        std::string previous=Meta("journal_head",std::string(96,'0'));
        Json body=Object();
        body.pushKV("kind",std::string(kind));
        body.pushKV("subject",std::string(subject));
        body.pushKV("metadata",payload);
        body.pushKV("previous",previous);
        const auto canonical=Canonical(body);
        auto digest=DomainHash("BTX/SecurityJournal/v1",canonical);
        Exec("INSERT INTO events(kind,subject,payload,previous,digest) VALUES(?,?,?,?,?)", {
            std::string(kind),std::string(subject),canonical,previous,digest
        });
        SetMeta("journal_head",digest);
    }
    bool Database::VerifyJournal() {
        std::string previous(96,'0');
        uint64_t cursor=0;
        while(true) {
            auto rows=Query("SELECT seq,payload,previous,digest FROM events WHERE seq>? ORDER BY seq LIMIT 256", {
                std::to_string(cursor)
            });
            if(rows.empty())break;
            for(const auto& r:rows) {
                if(r[2]!=previous||DomainHash("BTX/SecurityJournal/v1",r[1])!=r[3])return false;
                previous=r[3];
                cursor=ParseUInt(r[0]);
            }
        }
        return previous==Meta("journal_head",std::string(96,'0'));
    }
    bool Database::Revoked(std::string_view subject,int64_t now) {
        (void)now;
        return !Query("SELECT subject FROM revoked WHERE subject=?", {
            std::string(subject)
        }).empty();
    }
    void Database::Revoke(std::string_view subject,std::string_view notice,uint64_t epoch,int64_t now) {
        Require(IsHash(subject)&&IsHash(notice),"SEC_DIGEST");
        Exec("INSERT INTO revoked(subject,notice,epoch,at_ms) VALUES(?,?,?,?) ON CONFLICT(subject) DO UPDATE SET notice=excluded.notice,epoch=excluded.epoch,at_ms=excluded.at_ms WHERE excluded.epoch>revoked.epoch",
        {
            std::string(subject),std::string(notice),std::to_string(epoch),std::to_string(now)
        });
    }
    void Database::LinkParent(std::string_view child,std::string_view parent) {
        Require(IsHash(child)&&IsHash(parent)&&child!=parent,"SEC_ANCESTRY");
        std::vector<std::string> todo {
            std::string(parent)
        };
        std::set<std::string> seen;
        while(!todo.empty()) {
            auto x=todo.back();
            todo.pop_back();
            Require(x!=child,"SEC_ANCESTRY_CYCLE");
            if(!seen.insert(x).second)continue;
            Require(seen.size()<=256,"SEC_ANCESTRY_LIMIT");
            for(const auto& r:Query("SELECT parent FROM ancestry WHERE child=?", {
                x
            }))todo.push_back(r[0]);
        }
        Exec("INSERT OR IGNORE INTO ancestry(child,parent) VALUES(?,?)", {
            std::string(child),std::string(parent)
        });
    }
    bool Database::AncestryRevoked(std::string_view child,int64_t now) {
        std::vector<std::string> todo {
            std::string(child)
        };
        std::set<std::string> seen;
        while(!todo.empty()) {
            auto x=todo.back();
            todo.pop_back();
            if(!seen.insert(x).second)continue;
            Require(seen.size()<=256,"SEC_ANCESTRY_LIMIT");
            if(Revoked(x,now))return true;
            for(const auto& r:Query("SELECT parent FROM ancestry WHERE child=?", {
                x
            }))todo.push_back(r[0]);
        }
        return false;
    }
}
// namespace modelnet::security

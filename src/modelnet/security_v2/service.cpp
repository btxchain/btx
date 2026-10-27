// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/service.h>
#include <modelnet/security_v2/mesh.h>
#include <modelnet/security_v2/work.h>
#include <chrono>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#else
#include <windows.h>
#endif
namespace modelnet::security {
    namespace {
        uint64_t SteadyMs() {
            return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        }
        Json Ok() {
            Json x=Object();
            x.pushKV("ok",true);
            return x;
        }
    }
    struct Service::Impl {
        fs::path root;
        std::string boot;
        std::atomic<bool> stop {
            false
        };
        std::mutex mutex;
        std::condition_variable condition;
        struct Task {
            std::string id,name,phase {
                "queued"
            };
            Json request,result;
            uint64_t expires {
                0
            };
            bool internal {
                false
            };
        };
        std::map<std::string,std::shared_ptr<Task>> tasks;
        std::deque<std::shared_ptr<Task>> queue;
        std::set<std::string> internal_running;
        std::vector<std::thread> workers;
        std::thread maintenance;
#ifndef _WIN32
        int lock_fd {
            -1
        };
#else
        HANDLE lock_file {
            INVALID_HANDLE_VALUE
        };
#endif
        explicit Impl(fs::path directory):root(std::move(directory)),boot(Hex(RandomBytes(32))) {
            EnsurePrivateDirectory(root);
#ifndef _WIN32
            lock_fd=open((root/"guard.lock").c_str(),O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
            if (lock_fd < 0) throw Error("SEC_GUARD_ALREADY_OWNED");
            if (flock(lock_fd,LOCK_EX|LOCK_NB) != 0) {
                close(lock_fd);
                lock_fd=-1;
                throw Error("SEC_GUARD_ALREADY_OWNED");
            }
#else
            lock_file=CreateFileW((root/"guard.lock").c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,nullptr);
            Require(lock_file!=INVALID_HANDLE_VALUE,"SEC_GUARD_ALREADY_OWNED");
#endif
            Database db(root);
            {
                Database::Transaction tx(db);
                db.SetMeta("guard_boot",boot);
                db.SetMeta("runtime_available","1");
                db.Exec("UPDATE permits SET phase='revoked' WHERE phase IN ('prepared','executing')");
                db.Exec("UPDATE jobs SET phase='interrupted' WHERE phase IN ('queued','running')");
                db.Exec("UPDATE evaluation_runs SET phase='interrupted' WHERE phase='running'");
                db.Event("guard-started",boot,Object());
                tx.Commit();
            }
            try {
                for(unsigned i=0; i<2; ++i)workers.emplace_back([this] {
                    Worker();
                });
                maintenance=std::thread([this] {
                    Maintain();
                });
            }
            catch(...) {
                stop=true;
                condition.notify_all();
                for(auto& w:workers)if(w.joinable())w.join();
                throw;
            }
        }
        ~Impl() {
            stop=true;
            try {
                Database db(root);
                Database::Transaction tx(db);
                db.SetMeta("runtime_available","0");
                db.Exec("UPDATE permits SET phase='revoked' WHERE phase IN ('prepared','executing')");
                db.Event("guard-stopping",boot,Object());
                tx.Commit();
            }
            catch(...) {
            }
            condition.notify_all();
            if(maintenance.joinable())maintenance.join();
            for(auto& w:workers)if(w.joinable())w.join();
#ifndef _WIN32
            if(lock_fd>=0)close(lock_fd);
#else
            if(lock_file!=INVALID_HANDLE_VALUE)CloseHandle(lock_file);
#endif
        }
        Json Submit(const Json& request,bool internal=false,std::string name= {
        }) {
            auto task=std::make_shared<Task>();
            task->id=DomainHash("BTX/LocalJob/v1",Hex(RandomBytes(32)));
            task->request=request;
            task->internal=internal;
            task->name=std::move(name);
            {
                std::lock_guard lock(mutex);
                Require(!stop&&queue.size()<8,"SEC_JOB_QUEUE_LIMIT");
                for(auto it=tasks.begin(); it!=tasks.end(); ) {
                    if(it->second->expires&&it->second->expires<=SteadyMs())it=tasks.erase(it);
                    else ++it;
                }
                Require(tasks.size()<64,"SEC_JOB_RESULT_LIMIT");
                if(internal)Require(internal_running.insert(task->name).second,"SEC_JOB_ALREADY_RUNNING");
                tasks.emplace(task->id,task);
                queue.push_back(task);
            }
            condition.notify_all();
            Json out=Ok();
            out.pushKV("job",task->id);
            out.pushKV("phase","queued");
            out.pushKV("dispatched",false);
            return out;
        }
        Json Perform(Database& db,const Json& request) {
            const auto op=Text(request,"op",64);
            const auto now=NowMs();
            Broker broker(db,boot);
            if(op=="execute") {
                Fields(request, {
                    "op","secret","context","request"
                });
                return broker.Execute(Text(request,"secret",64),request["context"],request["request"],now);
            }
            if(op=="work") {
                Fields(request,{"op","id"});
                return ExecuteMeshWork(db,DigestField(request,"id"),now);
            }
            if(op=="evaluate") {
                Fields(request, {
                    "op","challenge"
                });
                return EvaluateChallenge(db,DigestField(request,"challenge"),now);
            }
            if(op=="canary") {
                Fields(request, {
                    "op","channel"
                });
                auto receipt=RunChannelCanary(db,Text(request,"channel",128),now);
                Lifecycle(db).Observe(Text(request,"channel",128),RecordId(receipt),NowMs());
                auto out=Ok();
                out.pushKV("receipt",RecordId(receipt));
                return out;
            }
            if(op=="resident-import") {
                Fields(request, {
                    "op","composition","source","byte_budget"
                });
                auto policy=Policy::Load(db,now);
                auto root_path=ImportResident(db,policy,DigestField(request,"composition"),NativePath(Text(request,
                "source")),UInt(request,"byte_budget",1ull<<44),now);
                (void)root_path;
                auto out=Ok();
                out.pushKV("composition",request["composition"]);
                return out;
            }
            if(op=="stage") {
                Fields(request, {
                    "op","update"
                });
                Lifecycle(db).Stage(DigestField(request,"update"),now);
                return Ok();
            }
            throw Error("SEC_JOB_OPERATION");
        }
        void Worker() {
            while(true) {
                std::shared_ptr<Task> task;
                {
                    std::unique_lock lock(mutex);
                    condition.wait(lock,[&] {
                        return stop||!queue.empty();
                    });
                    if(stop)return;
                    task=queue.front();
                    queue.pop_front();
                    task->phase="running";
                }
                Json result;
                try {
                    Database db(root);
                    result=Perform(db,task->request);
                }
                catch(const Error& e) {
                    result=Failure(e.code);
                }
                catch(...) {
                    result=Failure("SEC_JOB_EXCEPTION");
                }
                {
                    std::lock_guard lock(mutex);
                    task->result=std::move(result);
                    task->phase="finished";
                    task->expires=SteadyMs()+60000;
                    if(task->internal) {
                        internal_running.erase(task->name);
                        tasks.erase(task->id);
                    }
                }
            }
        }
        void Maintain() {
            while(!stop) {
                try {
                    Database db(root);
                    const auto now=NowMs();
                    if(!db.Meta("active_policy").empty()) {
                        const auto p=Policy::Load(db,now);
                        MeshTick(db,now);
                        Lifecycle lifecycle(db);
                        lifecycle.Tick(now);
                        auto local=ReadLocalConfig(db);
                        const bool allowed=local["execution_policy"].isObject()&&
                        local["execution_policy"]["allow_evaluation"].isBool()&&
                        local["execution_policy"]["allow_evaluation"].get_bool()&&db.Meta("paused","0")=="0";
                        if(allowed) {
                            // A channel gets actual local canary work, not a timer-only pass.
                            for(const auto& row:db.Query("SELECT name,candidate FROM channels WHERE phase='canary' ORDER BY name LIMIT 2")) {
                                const auto name="canary:"+row[0];
                                bool running;
                                {
                                    std::lock_guard lock(mutex);
                                    running=internal_running.contains(name);
                                }
                                if(!running) {
                                    Json r=Object();
                                    r.pushKV("op","canary");
                                    r.pushKV("channel",row[0]);
                                    Submit(r,true,name);
                                }
                            }
                            // Remote challenges are merely proposals. Only locally installed,
                            // owner-reviewed packages under a persistent compute grant can run.
                            if(local["identity"].isObject()) {
                                const auto evaluator=KeyId(Unhex(Text(local["identity"],"public_key",PK_BYTES*2),
                                PK_BYTES));
                                for(const auto& row:db.Query("SELECT id FROM challenges WHERE id NOT IN (SELECT challenge FROM evaluation_runs WHERE evaluator=?) ORDER BY id LIMIT 2",
                                {
                                    evaluator
                                })) {
                                    const auto challenge=db.Get(row[0]);
                                    const auto package=DigestField(challenge["body"],"package");
                                    if(!local["evaluation_plans"].isObject()||!local["evaluation_plans"].exists(package))continue;
                                    auto name="evaluate:"+row[0];
                                    bool running;
                                    {
                                        std::lock_guard lock(mutex);
                                        running=internal_running.contains(name);
                                    }
                                    if(!running) {
                                        Json r=Object();
                                        r.pushKV("op","evaluate");
                                        r.pushKV("challenge",row[0]);
                                        Submit(r,true,name);
                                    }
                                }
                            }
                        }
                        if(local["remote_work"].isObject()&&
                           local["remote_work"]["enabled"].isBool()&&
                           local["remote_work"]["enabled"].get_bool()&&
                           db.Meta("paused","0")=="0"){
                            const auto me=LoadLocalIdentity(db,p,"worker",now);
                            const auto worker=KeyId(me.public_key);
                            for(const auto& row:db.Query("SELECT id FROM objects WHERE kind='work' ORDER BY id LIMIT 64")){
                                MeshTables(db);
                                const auto work=db.Get(row[0]);
                                const auto& body=work["body"];
                                const auto target=Text(body,"target_host",128);
                                if(target!="any"&&target!=Text(local,"host",128))continue;
                                if(!db.Query("SELECT work FROM mesh_work_runs WHERE work=? AND worker=?",{row[0],worker}).empty())continue;
                                auto pkgs=StringArray(local["remote_work"]["packages"],128);
                                if(std::find(pkgs.begin(),pkgs.end(),DigestField(body,"package"))==pkgs.end())continue;
                                const auto name="work:"+row[0];
                                bool running;
                                {std::lock_guard lock(mutex);running=internal_running.contains(name);}
                                if(!running){Json r=Object();r.pushKV("op","work");r.pushKV("id",row[0]);Submit(r,true,name);}
                            }
                        }
                        Database::Transaction tx(db);
                        db.SetMeta("maintenance_error","");
                        db.SetMeta("maintenance_at",std::to_string(now));
                        tx.Commit();
                    }
                }
                catch(const Error& e) {
                    try {
                        Database db(root);
                        db.SetMeta("maintenance_error",e.code);
                    }
                    catch(...) {
                    }
                }
                catch(...) {
                    try {
                        Database db(root);
                        db.SetMeta("maintenance_error","SEC_MAINTENANCE_EXCEPTION");
                    }
                    catch(...) {
                    }
                }
                std::unique_lock lock(mutex);
                condition.wait_for(lock,std::chrono::seconds(2),[&] {
                    return stop.load();
                });
            }
        }
        Json Take(Database& db,const std::string& id,bool consume) {
            std::shared_ptr<Task> task;
            {
                std::lock_guard lock(mutex);
                auto it=tasks.find(id);
                Require(it!=tasks.end(),"SEC_JOB_ABSENT");
                task=it->second;
                Json out=Ok();
                out.pushKV("job",id);
                out.pushKV("phase",task->phase);
                if(task->phase!="finished")return out;
                if(consume)tasks.erase(id);
            }
            Require(task->expires>SteadyMs(),"SEC_JOB_EXPIRED");
            Json result=task->result;
            // A queued response does not preserve authority after revocation.
            if(Text(task->request,"op")=="execute"&&result.exists("output_hex")) {
                const auto permit=DomainHash("BTX/ActionBearer/v2",Text(task->request,"secret",64));
                auto rows=db.Query("SELECT grant_id FROM permits WHERE id=?", {
                    permit
                });
                if(rows.size()!=1||!Broker(db,boot).CanRelease(rows[0][0],task->request["context"],task->request["request"],
                NowMs()))
                result=Failure("SEC_RESPONSE_RELEASE_REVOKED");
            }
            if(!consume&&result.exists("output_hex")) {
                Json metadata=Object();
                auto names=result.getKeys();
                auto values=result.getValues();
                for(size_t i=0; i<names.size(); ++i)if(names[i]!="output_hex")metadata.pushKV(names[i],values[i]);
                result=std::move(metadata);
            }
            Json out=Ok();
            out.pushKV("job",id);
            out.pushKV("phase","finished");
            out.pushKV("result",result);
            return out;
        }
    };
    Service::Service(fs::path root):m(std::make_unique<Impl>(std::move(root))) {
    }
    Service::~Service()=default;
    Json Service::Handle(const Json& r) {
        try {
            (void)Canonical(r);
            const auto op=Text(r,"op",64);
            Database db(m->root);
            const auto now=NowMs();
            if(op=="execute"||op=="evaluate"||op=="canary"||op=="resident-import"||op=="stage"||op=="work")return m->Submit(r);
            if(op=="status") {
                Fields(r, {
                    "op"
                });
                auto out=Ok();
                out.pushKV("schema","BTX/SecurityService/v1");
                out.pushKV("guard_boot",m->boot);
                out.pushKV("automatic_spend_atoms","0");
                out.pushKV("policy_installed",!db.Meta("active_policy").empty());
                out.pushKV("paused",db.Meta("paused","0")=="1");
                out.pushKV("journal_valid",db.VerifyJournal());
                out.pushKV("channels",Lifecycle(db).Status());
                out.pushKV("maintenance_error",db.Meta("maintenance_error"));
                out.pushKV("release_qualification","NOT_ESTABLISHED_BY_COMPONENT_SERVICE");
                out.pushKV("model_safety_proven",false);
                out.pushKV("multi_host_security",MeshStatus(db,now));
                out.pushKV("continuous_protection_required",db.Meta("mesh_required","0")=="1");
                out.pushKV("protected_execution_scope","SECURITY_V2_BROKER_AND_LINUX_STATIC_FD_ONLY");
                out.pushKV("legacy_generatemodel_mediated",false);
                out.pushKV("general_gpu_runtime_qualified",false);
                return out;
            }
            if(op=="install-policy") {
                Fields(r, {
                    "op","record"
                });
                InstallPolicy(db,r["record"],now);
                return Ok();
            }
            if(op=="import") {
                Fields(r, {
                    "op","record"
                });
                const auto p=Policy::Load(db,now);
                ImportRecord(db,p,r["record"],now);
                auto out=Ok();
                out.pushKV("id",RecordId(r["record"]));
                return out;
            }
            if(op=="get") {
                Fields(r, {
                    "op","id"
                });
                auto out=Ok();
                out.pushKV("record",db.Get(DigestField(r,"id")));
                return out;
            }
            if(op=="admit") {
                Fields(r, {
                    "op","capsule"
                });
                auto p=Policy::Load(db,now);
                return SecurityStatus(db,p,DigestField(r,"capsule"),now);
            }
            if(op=="follow") {
                Fields(r, {
                    "op","mandate"
                });
                Lifecycle(db).Follow(DigestField(r,"mandate"),now);
                return Ok();
            }
            if(op=="observe") {
                Fields(r, {
                    "op","channel","receipt"
                });
                Lifecycle(db).Observe(Text(r,"channel",128),DigestField(r,"receipt"),now);
                return Ok();
            }
            if(op=="activate") {
                Fields(r, {
                    "op","channel"
                });
                Lifecycle(db).Activate(Text(r,"channel",128),now);
                return Ok();
            }
            if(op=="prepare") {
                Fields(r, {
                    "op","grant","context","request"
                });
                return Broker(db,m->boot).Prepare(DigestField(r,"grant"),r["context"],r["request"],now);
            }
            if(op=="pause") {
                Fields(r, {
                    "op"
                });
                Broker(db,m->boot).Pause(now);
                return Ok();
            }
            if(op=="resume") {
                Fields(r, {
                    "op","record"
                });
                Broker(db,m->boot).Resume(r["record"],now);
                return Ok();
            }
            if(op=="take"||op=="poll") {
                Fields(r, {
                    "op","job"
                });
                return m->Take(db,DigestField(r,"job"),op=="take");
            }
            if(op=="work-quorum"){
                Fields(r,{"op","id"});
                auto out=VerifyMeshWorkQuorum(db,DigestField(r,"id"),now);
                out.pushKV("ok",true);return out;
            }
            if(op=="mesh-enroll") {
                Fields(r,{"op","record"});
                const auto p=Policy::Load(db,now);
                const auto& record=r["record"];
                Require(Text(record,"kind")=="control"&&Text(record["body"],"operation")=="mesh-enroll",
                        "SEC_MESH_ENROLL_CONTROL");
                Require(MeshEnabled(db),"SEC_MESH_OWNER_CONFIG_ABSENT");
                ImportRecord(db,p,record,now);
                Database::Transaction tx(db);
                const auto id=RecordId(record);
                Require(db.Query("SELECT id FROM consumed_controls WHERE id=?",{id}).empty(),"SEC_MESH_ENROLL_REPLAY");
                db.Exec("INSERT INTO consumed_controls(id,at_ms) VALUES(?,?)",{id,std::to_string(now)});
                db.SetMeta("mesh_required","1");
                db.Exec("UPDATE permits SET phase='revoked' WHERE phase='prepared'");
                db.Event("mesh-enrolled",id,Object());tx.Commit();return Ok();
            }
            if(op=="mesh-export") {
                Fields(r,{"op","id"});
                MeshExport(db,DigestField(r,"id"),now);
                return Ok();
            }
            if(op=="mesh-status") {
                Fields(r,{"op"});
                auto status=MeshStatus(db,now);
                status.pushKV("ok",true);
                return status;
            }
            if(op=="publish") {
                Fields(r, {
                    "op","id"
                });
                PublishEvidenceClosure(db,DigestField(r,"id"),now);
                return Ok();
            }
            throw Error("SEC_OPERATION_DENIED");
        }
        catch(const Error& e) {
            return Failure(e.code);
        }
        catch(...) {
            return Failure("SEC_REQUEST_FAILED");
        }
    }
    std::string GuardProtocol::Handle(std::string_view line) {
        try {
            Require(line.size()<=4096&&line.find_first_of("\r\n\0",0,3)==std::string_view::npos,"SEC_FRAME");
            std::istringstream in {
                std::string(line)
            };
            std::string prefix,verb,extra;
            in>>prefix>>verb;
            Require(prefix=="SEC2","SEC_FRAME_VERSION");
            const auto now=SteadyMs();
            if(now>m_deadline) {
                m_input.clear();
                m_input_id.clear();
                m_output.clear();
                m_output_id.clear();
                m_expected=0;
            }
            if(verb=="BEGIN") {
                std::string id,number;
                Require(bool(in>>id>>number)&&!(in>>extra),"SEC_FRAME");
                Require(Unhex(id,16).size()==16,"SEC_FRAME_ID");
                const auto n=ParseUInt(number);
                Require(n>0&&n<=MAX_RECORD,"SEC_FRAME_LIMIT");
                m_input_id=id;
                m_input.clear();
                m_expected=n;
                m_output.clear();
                m_output_id.clear();
                m_deadline=now+10000;
                return "SEC2 READY "+id;
            }
            if(verb=="DATA") {
                std::string id,offset,hex;
                Require(bool(in>>id>>offset>>hex)&&!(in>>extra),"SEC_FRAME");
                Require(!m_input_id.empty()&&id==m_input_id&&ParseUInt(offset)==m_input.size(),"SEC_FRAME_ORDER");
                const auto bytes=Unhex(hex,1536);
                Require(!bytes.empty()&&bytes.size()<=m_expected-m_input.size(),"SEC_FRAME_LIMIT");
                m_input.append(reinterpret_cast<const char*>(bytes.data()),bytes.size());
                return "SEC2 STORED "+std::to_string(m_input.size());
            }
            if(verb=="COMMIT") {
                std::string id;
                Require(bool(in>>id)&&!(in>>extra)&&id==m_input_id&&m_input.size()==m_expected,"SEC_FRAME_INCOMPLETE");
                auto request=Parse(m_input);
                m_input.clear();
                m_input_id.clear();
                m_expected=0;
                m_output=Canonical(m_service.Handle(request));
                m_output_id=id;
                m_deadline=now+10000;
                return "SEC2 RESPONSE "+id+" "+std::to_string(m_output.size());
            }
            if(verb=="READ") {
                std::string id,offset;
                Require(bool(in>>id>>offset)&&!(in>>extra)&&id==m_output_id&&!id.empty(),"SEC_FRAME_RESPONSE");
                const auto begin=ParseUInt(offset);
                Require(begin<m_output.size(),"SEC_FRAME_OFFSET");
                const auto part=std::string_view(m_output).substr(begin,1536);
                auto response="SEC2 BYTES "+std::to_string(begin)+" "+Hex(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(part.data()),
                part.size()));
                if(begin+part.size()==m_output.size()) {
                    m_output.clear();
                    m_output_id.clear();
                }
                return response;
            }
            throw Error("SEC_FRAME_VERB");
        }
        catch(const Error& e) {
            m_input.clear();
            m_input_id.clear();
            m_output.clear();
            m_output_id.clear();
            m_expected=0;
            return "ERR "+e.code;
        }
        catch(...) {
            return "ERR SEC_FRAME_EXCEPTION";
        }
    }
}
// namespace modelnet::security

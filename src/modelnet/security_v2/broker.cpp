// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/broker.h>
#include <modelnet/security_v2/mesh.h>
#include <algorithm>
#include <array>
#include <set>
#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif
namespace modelnet::security {
    namespace {
        std::string SelectComposition(Database& db,const Json& grant) {
            if(!grant["composition"].get_str().empty())return DigestField(grant,"composition");
            auto rows=db.Query("SELECT active,phase FROM channels WHERE name=?", {
                Text(grant,"channel",128)
            });
            Require(rows.size()==1&&(rows[0][1]=="active"||rows[0][1]=="canary")&&!rows[0][0].empty(),"SEC_CHANNEL_NOT_ACTIVE");
            auto capsule=db.Get(rows[0][0]);
            return DigestField(capsule["body"],"composition");
        }
        bool Contains(const Json& a,const std::string& s) {
            auto xs=StringArray(a,256);
            return std::find(xs.begin(),xs.end(),s)!=xs.end();
        }
#ifndef _WIN32
        class Fd {
            public:int n;
            explicit Fd(int x):n(x) {
            }
            ~Fd() {
                if(n>=0)close(n);
            }
            Fd(const Fd&)=delete;
        };
        int OpenRelative(int root,std::string_view name,int flags) {
            Require(IsPortablePath(name),"SEC_RESOURCE_PATH");
            Fd dir(dup(root));
            Require(dir.n>=0,"SEC_RESOURCE_OPEN");
            size_t begin=0;
            while(true) {
                size_t end=name.find('/',begin);
                std::string part(name.substr(begin,end==name.npos?name.size()-begin:end-begin));
                if(end==name.npos)return openat(dir.n,part.c_str(),flags|O_NOFOLLOW|O_CLOEXEC,0600);
                int next=openat(dir.n,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
                Require(next>=0,"SEC_RESOURCE_COMPONENT");
                close(dir.n);
                dir.n=next;
                begin=end+1;
            }
        }
        std::string ReadResource(const fs::path& workspace,const std::string& name,uint64_t cap) {
            Fd root(open(workspace.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
            Require(root.n>=0,"SEC_WORKSPACE_OPEN");
            Fd file(OpenRelative(root.n,name,O_RDONLY));
            Require(file.n>=0,"SEC_RESOURCE_DENIED");
            struct stat st {
            };
            Require(fstat(file.n,&st)==0&&S_ISREG(st.st_mode)&&st.st_nlink==1&&st.st_size>=0&&static_cast<uint64_t>(st.st_size)<=cap,
            "SEC_RESOURCE_TYPE_OR_LIMIT");
            std::string out;
            std::array<char,8192> b {
            };
            while(true) {
                ssize_t n=read(file.n,b.data(),b.size());
                if(n<0&&errno==EINTR)continue;
                Require(n>=0,"SEC_RESOURCE_READ");
                if(n==0)break;
                Require(out.size()+static_cast<size_t>(n)<=cap,"SEC_RESOURCE_LIMIT");
                out.append(b.data(),n);
            }
            Require(out.size()==static_cast<size_t>(st.st_size),"SEC_RESOURCE_CHANGED");
            return out;
        }
        void WriteResource(const fs::path& workspace,const std::string& name,std::string_view value)
        {
            Require(IsPortablePath(name),"SEC_RESOURCE_PATH");
            Fd parent(open(workspace.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
            Require(parent.n>=0,"SEC_WORKSPACE_OPEN");
            size_t begin=0;
            while(true) {
                const auto slash=name.find('/',begin);
                if(slash==std::string::npos)break;
                const auto part=name.substr(begin,slash-begin);
                const int next=openat(parent.n,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
                Require(next>=0,"SEC_RESOURCE_COMPONENT");
                close(parent.n);
                parent.n=next;
                begin=slash+1;
            }
            const auto leaf=name.substr(begin),temporary=".btx-output-"+Hex(RandomBytes(16));
            Fd file(openat(parent.n,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
            Require(file.n>=0,"SEC_RESOURCE_CREATE");
            try {
                size_t done=0;
                while(done<value.size()) {
                    const auto n=write(file.n,value.data()+done,value.size()-done);
                    if(n<0&&errno==EINTR)continue;
                    Require(n>0,"SEC_RESOURCE_WRITE");
                    done+=n;
                }
                Require(fsync(file.n)==0,"SEC_RESOURCE_SYNC");
                // Publish a complete file without ever replacing an existing path.
                Require(linkat(parent.n,temporary.c_str(),parent.n,leaf.c_str(),0)==0,"SEC_WRITE_NEW_ONLY");
                Require(unlinkat(parent.n,temporary.c_str(),0)==0&&fsync(parent.n)==0,"SEC_RESOURCE_SYNC");
            }
            catch(...) {
                unlinkat(parent.n,temporary.c_str(),0);
                throw;
            }
        }
#else
        // Keep every directory component open without write/delete sharing. This both
        // refuses reparse points and prevents a checked directory being renamed or
        // retargeted before the final open. Only local-drive workspaces are supported.
        struct WinHandles {
            std::vector<HANDLE> values;
            ~WinHandles() {
                for(auto h:values)if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);
            }
            void Hold(HANDLE h) {
                Require(h!=INVALID_HANDLE_VALUE,"SEC_WINDOWS_OPEN");
                values.push_back(h);
            }
        };
        fs::path LockParents(WinHandles& handles,const fs::path& workspace,const std::string& name) {
            Require(workspace.is_absolute()&&IsPortablePath(name),"SEC_WORKSPACE_ROOT");
            const auto full=workspace/NativePath(name);
            Require(full.root_name().native().size()==2&&full.root_name().native()[1]==L':',"SEC_WINDOWS_LOCAL_DRIVE_ONLY");
            auto walk=full.root_path();
            Require(GetDriveTypeW(walk.c_str())!=DRIVE_REMOTE,"SEC_WINDOWS_LOCAL_DRIVE_ONLY");
            auto hold_directory=[&](const fs::path& path) {
                HANDLE h=CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_SHARE_READ,nullptr,
                OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
                handles.Hold(h);
                BY_HANDLE_FILE_INFORMATION info {
                };
                Require(GetFileInformationByHandle(h,&info)&&
                (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&
                !(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),"SEC_WINDOWS_REPARSE");
            };
            hold_directory(walk);
            const auto parent=full.parent_path();
            for(const auto& part:parent.relative_path()) {
                Require(part!=L"."&&part!=L"..","SEC_WINDOWS_PATH");
                walk/=part;
                hold_directory(walk);
            }
            return full;
        }
        std::string ReadResource(const fs::path& workspace,const std::string& name,uint64_t cap) {
            WinHandles handles;
            const auto path=LockParents(handles,workspace,name);
            HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
            handles.Hold(h);
            BY_HANDLE_FILE_INFORMATION info {
            };
            LARGE_INTEGER length {
            };
            Require(GetFileType(h)==FILE_TYPE_DISK&&GetFileInformationByHandle(h,&info)&&info.nNumberOfLinks==1&&
            !(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&
            GetFileSizeEx(h,&length)&&length.QuadPart>=0&&static_cast<uint64_t>(length.QuadPart)<=cap,
            "SEC_RESOURCE_TYPE_OR_LIMIT");
            std::string out(static_cast<size_t>(length.QuadPart),'\0');
            size_t offset=0;
            while(offset<out.size()) {
                DWORD got=0;
                Require(::ReadFile(h,out.data()+offset,static_cast<DWORD>(std::min<size_t>(out.size()-offset,65536)),&got,
                nullptr)&&got>0,
                "SEC_RESOURCE_READ");
                offset+=got;
            }
            return out;
        }
        void WriteResource(const fs::path& workspace,const std::string& name,std::string_view value) {
            WinHandles handles;
            const auto path=LockParents(handles,workspace,name);
            // WritePrivate uses an owner/SYSTEM DACL, an exclusive destination, and an
            // atomic non-replacing publication. Parent locks stay held for the operation.
            WritePrivate(path,value,false);
        }
#endif
        void CheckWorkspace(const fs::path& root) {
            Require(root.is_absolute(),"SEC_WORKSPACE_ROOT");
            fs::path walk=root.root_path();
            for(const auto& p:root.relative_path()) {
                Require(p!=".."&&p!=".","SEC_WORKSPACE_ROOT");
                walk/=p;
                auto st=fs::symlink_status(walk);
                Require(fs::is_directory(st)&&!fs::is_symlink(st),"SEC_WORKSPACE_SYMLINK");
            }
        }
    }
    std::string ContextDigest(const Json& c) {
        Fields(c, {
            "realm","composition","runtime","tool_schema","session"
        });
        for(auto k: {
            "realm","composition","runtime","tool_schema"
        })DigestField(c,k);
        Require(Unhex(Text(c,"session",64),32).size()==32,"SEC_SESSION");
        return DomainHash("BTX/ActionContext/v2",Canonical(c));
    }
    std::string RequestDigest(const Json& r) {
        Fields(r, {
            "tool"
        }, {
            "path","payload_hex","package"
        });
        auto tool=Text(r,"tool",32);
        Require(tool=="read"||tool=="hash"||tool=="write-new"||tool=="run-static","SEC_TOOL_DENIED");
        if(tool=="run-static") {
            Fields(r, {
                "tool","package","payload_hex"
            });
            DigestField(r,"package");
            Require(r["payload_hex"].isStr(),"SEC_PAYLOAD");
            Unhex(r["payload_hex"].get_str(),65536);
        }
        else {
            Require(r.exists("path")&&IsPortablePath(Text(r,"path",1024))&&!IsCredentialPath(Text(r,"path",1024)),
            "SEC_PROTECTED_RESOURCE");
            if(tool=="write-new") {
                Fields(r, {
                    "tool","path","payload_hex"
                });
                Require(r["payload_hex"].isStr(),"SEC_PAYLOAD");
                Require(r["payload_hex"].isStr(),"SEC_PAYLOAD");
                Unhex(r["payload_hex"].get_str(),65536);
            }
            else Fields(r, {
                "tool","path"
            });
        }
        return DomainHash("BTX/ActionArguments/v2",Canonical(r));
    }
    void ValidateGrant(const Json& g) {
        Fields(g, {
            "realm","policy_epoch","composition","channel","capsule","runtime","tool_schema","session","workspace",
            "tools","read_paths","write_paths","packages","max_calls","max_bytes","per_action_bytes","issued_ms","expires_ms"
        });
        DigestField(g,"realm");
        UInt(g,"policy_epoch");
        for(auto n: {
            "composition","channel","capsule"
        })Require(g[n].isStr(),"SEC_GRANT_BINDING");
        Require(g["composition"].get_str().empty()!=g["channel"].get_str().empty(),"SEC_GRANT_BINDING");
        if(!g["composition"].get_str().empty()) {
            DigestField(g,"composition");
            DigestField(g,"capsule");
            Require(g["channel"].get_str().empty(),"SEC_GRANT_BINDING");
        }
        else {
            Text(g,"channel",128);
            Require(g["capsule"].get_str().empty(),"SEC_GRANT_BINDING");
        }
        DigestField(g,"runtime");
        DigestField(g,"tool_schema");
        Require(Unhex(Text(g,"session",64),32).size()==32,"SEC_SESSION");
        Text(g,"workspace",128);
        for(const auto& t:StringArray(g["tools"],4))Require(t=="read"||t=="hash"||t=="write-new"||t=="run-static",
        "SEC_TOOL_DENIED");
        for(auto k: {
            "read_paths","write_paths"
        })for(const auto& path:StringArray(g[k],256))Require(IsPortablePath(path)&&!IsCredentialPath(path),"SEC_PROTECTED_RESOURCE");
        for(const auto& id:StringArray(g["packages"],32))Require(IsHash(id),"SEC_PACKAGE");
        Require(UInt(g,"max_calls",1000000)>0&&UInt(g,"max_bytes",1ull<<40)>0&&UInt(g,"per_action_bytes",65536)>0,
        "SEC_GRANT_LIMIT");
        auto a=UInt(g,"issued_ms",INT64_MAX),b=UInt(g,"expires_ms",INT64_MAX);
        Require(b>a&&b-a<=86400000,"SEC_GRANT_TTL");
    }
    Broker::Broker(Database& db,std::string boot):m_db(db),m_boot(std::move(boot)) {
        Require(m_boot.size()==64,"SEC_BOOT");
    }
    Json Broker::LocalConfig() {
        auto c=Parse(ReadFile(m_db.Root()/"local.json",MAX_RECORD,true));
        Fields(c, {
            "schema","workspaces","packages","host"
        }, {
            "evaluation_plans","runtimes","identity","peer_identity","execution_policy","continuous_security"
        });
        Require(Text(c,"schema")=="BTX/SecurityLocal/v1"&&c["workspaces"].isObject()&&c["packages"].isObject(),
        "SEC_LOCAL_CONFIG");
        Text(c,"host",128);
        return c;
    }
    Json Broker::Authorize(const Policy& p,const std::string& id,const Json& context,const Json& request,int64_t now) {
        (void)ContextDigest(context);
        (void)RequestDigest(request);
        Require(!m_db.Revoked(id,now)&&m_db.Meta("paused","0")=="0","SEC_GRANT_REVOKED_OR_PAUSED");
        auto e=m_db.Get(id);
        Require(Text(e,"kind")=="grant","SEC_GRANT_KIND");
        p.Check(e,"owner",m_db,now);
        const auto& g=e["body"];
        ValidateGrant(g);
        Require(DigestField(g,"realm")==p.realm&&DigestField(context,"realm")==p.realm&&UInt(g,"policy_epoch")==p.epoch,
        "SEC_POLICY_BINDING");
        Require(UInt(g,"issued_ms",INT64_MAX)<=static_cast<uint64_t>(now)&&static_cast<uint64_t>(now)<UInt(g,"expires_ms",
        INT64_MAX),"SEC_GRANT_EXPIRED");
        auto composition=SelectComposition(m_db,g);
        Require(composition==DigestField(context,"composition"),"SEC_GENERATION_CHANGED");
        std::string capsule=g["capsule"].get_str();
        if(capsule.empty()) {
            auto rows=m_db.Query("SELECT active FROM channels WHERE name=?", {
                Text(g,"channel")
            });
            Require(rows.size()==1,"SEC_CHANNEL");
            capsule=rows[0][0];
        }
        auto admission=AdmitCapsule(m_db,p,capsule,now);
        if(m_db.Meta("mesh_required","0")=="1")MeshRequireLive(m_db,p,capsule,now);
        Require(admission.composition_id==composition&&admission.profile=="restricted-tools","SEC_PROFILE_DENIED");
        Require(DigestField(context,"runtime")==DigestField(g,"runtime")&&admission.runtime==DigestField(g,"runtime")&&DigestField(context,
        "tool_schema")==DigestField(g,"tool_schema")&&admission.tool_schema==DigestField(g,"tool_schema")&&Text(context,
        "session")==Text(g,"session"),"SEC_CONTEXT_BINDING");
        const auto tool=Text(request,"tool");
        Require(Contains(g["tools"],tool),"SEC_TOOL_DENIED");
        if(tool=="run-static")Require(Contains(g["packages"],DigestField(request,"package")),"SEC_PACKAGE_DENIED");
        else Require(Contains(g[tool=="write-new"?"write_paths":"read_paths"],Text(request,"path")),"SEC_RESOURCE_DENIED");
        return g;
    }
    Json Broker::Prepare(const std::string& id,const Json& context,const Json& request,int64_t now) {
        auto p=Policy::Load(m_db,now);
        Database::Transaction tx(m_db);
        m_db.CheckClock(now);
        auto g=Authorize(p,id,context,request,now);
        m_db.Exec("UPDATE permits SET phase='expired' WHERE phase='prepared' AND expires<=?",{std::to_string(now)});
        Require(ParseUInt(m_db.Query("SELECT count(*) FROM permits WHERE phase='prepared'")[0][0])<4096,"SEC_PERMIT_QUOTA");
        auto secret=Hex(RandomBytes(32));
        auto permit=DomainHash("BTX/ActionBearer/v2",secret);
        const auto expires=std::min<uint64_t>(static_cast<uint64_t>(now)+15000,UInt(g,"expires_ms",INT64_MAX));
        m_db.Exec("INSERT INTO permits(id,grant_id,context,request,boot,epoch,expires,phase) VALUES(?,?,?,?,?,?,?,'prepared')",
        {
            permit,id,ContextDigest(context),RequestDigest(request),m_boot,std::to_string(p.epoch),std::to_string(expires)
        });
        m_db.Event("permit-prepared",permit,Object());
        tx.Commit();
        Json out=Object();
        out.pushKV("ok",true);
        out.pushKV("permit",permit);
        out.pushKV("secret",secret);
        out.pushKV("expires_ms",expires);
        out.pushKV("dispatched",false);
        return out;
    }
    Json Broker::Dispatch(const Json& g,const Json&,const Json& r,const std::function<bool()>& authorized) {
        auto config=LocalConfig();
        const auto tool=Text(r,"tool");
        Json result=Object();
        result.pushKV("tool",tool);
        Require(authorized(),"SEC_REVOKED_BEFORE_EFFECT");
        uint64_t limit=UInt(g,"per_action_bytes",65536);
        if(tool=="run-static") {
            const auto package=DigestField(r,"package");
            Require(config["packages"].exists(package),"SEC_PACKAGE_UNINSTALLED");
            const auto& entry=config["packages"][package];
            Fields(entry, {
                "executable","sha384","sandbox","wall_ms","cpu_ms","memory_bytes"
            });
            Require(DigestField(entry,"sandbox")==StaticSandboxDigest(),"SEC_SANDBOX_PROFILE");
            auto public_entry=entry;
            Require(DomainHash("BTX/LocalStaticPackage/v1",Canonical(public_entry))==package,"SEC_PACKAGE_ID");
            auto bytes=Unhex(r["payload_hex"].get_str(),65536);
            SandboxLimits limits {
                UInt(entry,"memory_bytes",64ull<<30),UInt(entry,"wall_ms",600000),UInt(entry,"cpu_ms",600000),limit
            };
            auto run=RunStaticWorker(NativePath(Text(entry,"executable")),DigestField(entry,"sha384"),std::string_view(reinterpret_cast<const char*>(bytes.data()),
            bytes.size()),limits,authorized);
            Require(run.dispatched&&run.enforced,run.error.empty()?"SEC_NOT_DISPATCHED":run.error.c_str());
            Require(run.error.empty(),run.error.c_str());
            result.pushKV("dispatched",true);
            result.pushKV("sandbox_enforced",true);
            result.pushKV("sandbox",StaticSandboxDigest());
            result.pushKV("exit_code",run.exit_code);
            result.pushKV("output_hex",Hex(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(run.output.data()),
            run.output.size())));
            result.pushKV("output_digest",Hash(run.output));
            result.pushKV("output_bytes",static_cast<uint64_t>(run.output.size()));
            result.pushKV("elapsed_ms",run.elapsed_ms);
        }
        else {
            auto workspace=Text(g,"workspace",128);
            Require(config["workspaces"].exists(workspace)&&config["workspaces"][workspace].isStr(),"SEC_WORKSPACE_UNREGISTERED");
            fs::path root=NativePath(config["workspaces"][workspace].get_str());
            CheckWorkspace(root);
            auto path=Text(r,"path",1024);
            if(tool=="write-new") {
                auto data=Unhex(r["payload_hex"].get_str(),limit);
                WriteResource(root,path,std::string_view(reinterpret_cast<const char*>(data.data()),data.size()));
                result.pushKV("output_digest",Hash(data));
                result.pushKV("output_bytes",static_cast<uint64_t>(data.size()));
            }
            else {
                auto data=ReadResource(root,path,limit);
                result.pushKV("output_digest",Hash(data));
                result.pushKV("output_bytes",static_cast<uint64_t>(data.size()));
                if(tool=="read")result.pushKV("output_hex",Hex(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(data.data()),
                data.size())));
            }
            result.pushKV("dispatched",true);
            result.pushKV("sandbox_enforced",false);
            result.pushKV("boundary","DESCRIPTOR_SCOPED_BROKER");
        }
        Require(authorized(),"SEC_RELEASE_REVOKED");
        result.pushKV("ok",true);
        return result;
    }
    Json Broker::Execute(const std::string& secret,const Json& context,const Json& request,int64_t now) {
        Require(Unhex(secret,32).size()==32,"SEC_SECRET");
        const auto permit=DomainHash("BTX/ActionBearer/v2",secret);
        std::string grant;
        Json g;
        {
            Database::Transaction tx(m_db);
            m_db.CheckClock(now);
            auto rows=m_db.Query("SELECT grant_id,context,request,boot,epoch,expires,phase FROM permits WHERE id=?",
            {
                permit
            });
            Require(rows.size()==1,"SEC_PERMIT_ABSENT");
            const auto& row=rows[0];
            Require(row[6]=="prepared","SEC_PERMIT_REPLAY");
            Require(row[3]==m_boot&&ParseUInt(row[5])>static_cast<uint64_t>(now),"SEC_PERMIT_EXPIRED_OR_RESTARTED");
            Require(row[1]==ContextDigest(context)&&row[2]==RequestDigest(request),"SEC_ARGUMENT_SUBSTITUTION");
            auto p=Policy::Load(m_db,now);
            Require(ParseUInt(row[4])==p.epoch,"SEC_POLICY_CHANGED");
            grant=row[0];
            g=Authorize(p,grant,context,request,now);
            auto used=m_db.Query("SELECT calls,bytes FROM budgets WHERE grant_id=?", {
                grant
            });
            uint64_t calls=used.empty()?0:ParseUInt(used[0][0]),bytes=used.empty()?0:ParseUInt(used[0][1]),reserve=UInt(g,
            "per_action_bytes",65536);
            Require(calls<UInt(g,"max_calls",1000000)&&bytes<=UInt(g,"max_bytes",1ull<<40)&&reserve<=UInt(g,"max_bytes",
            1ull<<40)-bytes,"SEC_BUDGET_EXHAUSTED");
            m_db.Exec("INSERT INTO budgets(grant_id,calls,bytes) VALUES(?,?,?) ON CONFLICT(grant_id) DO UPDATE SET calls=excluded.calls,bytes=excluded.bytes",
            {
                grant,std::to_string(calls+1),std::to_string(bytes+reserve)
            });
            m_db.Exec("UPDATE permits SET phase='executing' WHERE id=?", {
                permit
            });
            m_db.Event("effect-started",permit,Object());
            tx.Commit();
        }
        auto authorized=[&]() {
            try {
                auto p=Policy::Load(m_db,NowMs());
                (void)Authorize(p,grant,context,request,NowMs());
                auto rows=m_db.Query("SELECT phase FROM permits WHERE id=?", {
                    permit
                });
                return rows.size()==1&&rows[0][0]=="executing";
            }
            catch(...) {
                return false;
            }
        };
        Json result;
        try {
            result=Dispatch(g,context,request,authorized);
        }
        catch(const Error& e) {
            result=Failure(e.code);
        }
        catch(...) {
            result=Failure("SEC_EFFECT_FAILED");
        }
        {
            Database::Transaction tx(m_db);
            bool release=authorized();
            if(!release)result=Failure("SEC_RELEASE_REVOKED");
            Json public_result=result;
            // Persist only result metadata; private file contents are never in the
            // durable action journal. An owner may independently retain a response.
            if(public_result.exists("output_hex")) {
                Json stripped=Object();
                const auto keys=public_result.getKeys();
                const auto values=public_result.getValues();
                for(size_t i=0; i<keys.size(); ++i)if(keys[i]!="output_hex")stripped.pushKV(keys[i],values[i]);
                public_result=stripped;
            }
            const bool ok=result["ok"].isBool()&&result["ok"].get_bool();
            m_db.Exec("UPDATE permits SET phase=?,result=?,error=? WHERE id=?", {
                ok?"completed":"failed",Canonical(public_result),ok?"":result["error"].get_str(),permit
            });
            m_db.Event(ok?"effect-completed":"effect-failed",permit,public_result);
            tx.Commit();
        }
        result.pushKV("permit",permit);
        result.pushKV("automatic_spend_atoms","0");
        return result;
    }
    Json Broker::Result(const std::string& id) {
        auto rows=m_db.Query("SELECT phase,result,error FROM permits WHERE id=?", {
            id
        });
        Require(rows.size()==1,"SEC_PERMIT_ABSENT");
        Json out=Object();
        out.pushKV("permit",id);
        out.pushKV("phase",rows[0][0]);
        out.pushKV("result",rows[0][1].empty()?Object():Parse(rows[0][1]));
        out.pushKV("error",rows[0][2]);
        out.pushKV("private_output_retained",false);
        return out;
    }
    bool Broker::CanRelease(const std::string& grant,const Json& context,const Json& request,int64_t now) {
        try {
            auto p=Policy::Load(m_db,now);
            (void)Authorize(p,grant,context,request,now);
            return true;
        }
        catch(...) {
            return false;
        }
    }
    void Broker::Pause(int64_t now) {
        Database::Transaction tx(m_db);
        m_db.CheckClock(now);
        m_db.SetMeta("paused","1");
        m_db.Exec("UPDATE permits SET phase='revoked' WHERE phase IN ('prepared','executing')");
        m_db.Event("paused","local",Object());
        tx.Commit();
    }
    void Broker::Resume(const Json& e,int64_t now) {
        auto p=Policy::Load(m_db,now);
        Require(Text(e,"kind")=="control","SEC_RESUME_AUTHORITY");
        p.Check(e,"owner",m_db,now);
        const auto& b=e["body"];
        Fields(b, {
            "realm","policy_epoch","operation","nonce","issued_ms","expires_ms"
        });
        Require(Text(b,"operation")=="resume" && DigestField(b,"realm")==p.realm &&
        UInt(b,"policy_epoch")==p.epoch,"SEC_RESUME_AUTHORITY");
        const auto issued=UInt(b,"issued_ms",INT64_MAX),expires=UInt(b,"expires_ms",INT64_MAX);
        Require(issued<=static_cast<uint64_t>(now)&&expires>static_cast<uint64_t>(now)&&
        expires>issued&&expires-issued<=60000,"SEC_RESUME_AUTHORITY");
        Require(Unhex(Text(b,"nonce",64),32).size()==32,"SEC_NONCE");
        Database::Transaction tx(m_db);
        m_db.CheckClock(now);
        const auto id=RecordId(e);
        Require(m_db.Query("SELECT id FROM consumed_controls WHERE id=?", {
            id
        }).empty(),"SEC_RESUME_REPLAY");
        m_db.Exec("INSERT INTO consumed_controls(id,at_ms) VALUES(?,?)", {
            id,std::to_string(now)
        });
        m_db.SetMeta("paused","0");
        m_db.Event("resumed",id,Object());
        tx.Commit();
    }
}
// namespace modelnet::security

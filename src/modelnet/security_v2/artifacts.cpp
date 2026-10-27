// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/security_v2/artifacts.h>
#include <crypto/sha384.h>
#include <array>
#include <fstream>
#include <set>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif
namespace modelnet::security {
    namespace {
        void PlainTreePath(const fs::path& path) {
            Require(path.is_absolute(), "SEC_ARTIFACT_ABSOLUTE");
            fs::path walk=path.root_path();
            for(const auto& part:path.relative_path()) {
                Require(part!="."&&part!="..", "SEC_ARTIFACT_PATH");
                walk/=part;
                auto status=fs::symlink_status(walk);
                Require(!fs::is_symlink(status), "SEC_ARTIFACT_SYMLINK");
#ifdef _WIN32
                // Also reject junctions and other Windows reparse points. Windows native
                // validation remains a release requirement, not a Linux test result.
                const DWORD attr=GetFileAttributesW(walk.c_str());
                Require(attr!=INVALID_FILE_ATTRIBUTES&&!(attr&FILE_ATTRIBUTE_REPARSE_POINT),"SEC_ARTIFACT_REPARSE");
#endif
            }
        }
        std::string Stream(const fs::path& source,uint64_t expected,const fs::path* output) {
            PlainTreePath(source);
            Require(fs::is_regular_file(fs::symlink_status(source))&&fs::hard_link_count(source)==1,
            "SEC_ARTIFACT_REGULAR");
            Require(fs::file_size(source)==expected,"SEC_ARTIFACT_SIZE");
            CSHA384 hash;
            std::array<unsigned char,1024*1024> buffer {
            };
            uint64_t total=0;
#ifndef _WIN32
            int in=open(source.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            Require(in>=0,"SEC_ARTIFACT_OPEN");
            struct Owner {
                int fd;
                ~Owner() {
                    if(fd>=0)close(fd);
                }
            }
            input {
                in
            },dest {
                -1
            };
            struct stat before {
            };
            Require(fstat(in,&before)==0&&S_ISREG(before.st_mode)&&before.st_nlink==1&&
            before.st_size>=0&&static_cast<uint64_t>(before.st_size)==expected,"SEC_ARTIFACT_REGULAR");
            if(output) {
                dest.fd=open(output->c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
                Require(dest.fd>=0,"SEC_ARTIFACT_CREATE");
            }
            while(true) {
                auto n=read(in,buffer.data(),buffer.size());
                if(n<0&&errno==EINTR)continue;
                Require(n>=0,"SEC_ARTIFACT_READ");
                if(n==0)break;
                Require(static_cast<uint64_t>(n)<=expected-total,"SEC_ARTIFACT_CHANGED");
                hash.Write(buffer.data(),static_cast<size_t>(n));
                total+=n;
                if(output) {
                    size_t done=0;
                    while(done<static_cast<size_t>(n)) {
                        auto wrote=write(dest.fd,buffer.data()+done,static_cast<size_t>(n)-done);
                        if(wrote<0&&errno==EINTR)continue;
                        Require(wrote>0,"SEC_ARTIFACT_WRITE");
                        done+=wrote;
                    }
                }
            }
            struct stat after {
            };
            Require(fstat(in,&after)==0&&before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&
            before.st_size==after.st_size,"SEC_ARTIFACT_CHANGED");
            if(output)Require(fsync(dest.fd)==0&&fchmod(dest.fd,0400)==0,"SEC_ARTIFACT_SYNC");
#else
            std::ifstream in(source,std::ios::binary);
            Require(in.good(),"SEC_ARTIFACT_OPEN");
            std::ofstream out;
            if(output) {
                Require(!fs::exists(*output),"SEC_ARTIFACT_EXISTS");
                out.open(*output,std::ios::binary);
                Require(out.good(),"SEC_ARTIFACT_CREATE");
            }
            while(in) {
                in.read(reinterpret_cast<char*>(buffer.data()),buffer.size());
                auto n=in.gcount();
                Require(n>=0&&static_cast<uint64_t>(n)<=expected-total,"SEC_ARTIFACT_CHANGED");
                hash.Write(buffer.data(),static_cast<size_t>(n));
                total+=n;
                if(output) {
                    out.write(reinterpret_cast<char*>(buffer.data()),n);
                    Require(out.good(),"SEC_ARTIFACT_WRITE");
                }
            }
            Require(!in.bad(),"SEC_ARTIFACT_READ");
            if(output) {
                out.flush();
                Require(out.good(),"SEC_ARTIFACT_SYNC");
            }
#endif
            Require(total==expected,"SEC_ARTIFACT_CHANGED");
            std::array<unsigned char,48> digest {
            };
            hash.Finalize(digest.data());
            return Hex(digest);
        }
        void Number(std::string& out,uint64_t n) {
            for(unsigned i=0; i<8; ++i)out.push_back(static_cast<char>((n>>(i*8))&255));
        }
    }
    std::string FileDigest(const fs::path& path,uint64_t bytes) {
        return Stream(path,bytes,nullptr);
    }
    fs::path VerifyResident(Database& db,const std::string& id) {
        auto e=db.Get(id);
        Require(Text(e,"kind")=="composition","SEC_COMPOSITION_KIND");
        ValidateComposition(e["body"]);
        const fs::path root=db.Root()/"artifacts"/id;
        Require(fs::is_directory(root),"SEC_RESIDENT_ABSENT");
        PlainTreePath(root);
        std::set<std::string> expected;
        for(const auto& f:e["body"]["files"].getValues()) {
            const auto path=Text(f,"path",1024);
            expected.insert(path);
            Require(FileDigest(root/NativePath(path),UInt(f,"bytes",1ull<<44))==DigestField(f,"sha384"),
            "SEC_RESIDENT_DIGEST");
        }
        size_t count=0;
        for(const auto& entry:fs::recursive_directory_iterator(root)) {
            Require(++count<=4096,"SEC_RESIDENT_TREE_LIMIT");
            const auto st=entry.symlink_status();
            Require(!fs::is_symlink(st),"SEC_RESIDENT_SYMLINK");
            if(fs::is_directory(st))continue;
            auto name=entry.path().lexically_relative(root).generic_string();
            Require(fs::is_regular_file(st)&&expected.contains(name),"SEC_RESIDENT_EXTRA_FILE");
        }
        return root;
    }
    fs::path ImportResident(Database& db,const Policy& p,const std::string& id,
    const fs::path& source,uint64_t budget,int64_t now) {
        auto e=db.Get(id);
        Require(Text(e,"kind")=="composition","SEC_COMPOSITION_KIND");
        p.Check(e,"publisher",db,now);
        ValidateComposition(e["body"]);
        Require(!db.AncestryRevoked(id,now),"SEC_QUARANTINE");
        Require(DigestField(e["body"],"realm")==p.realm&&UInt(e["body"],"policy_epoch")==p.epoch,
        "SEC_POLICY_BINDING");
        uint64_t total=0;
        for(const auto& f:e["body"]["files"].getValues()) {
            auto n=UInt(f,"bytes",1ull<<44);
            Require(n<=budget-total,"SEC_STORAGE_BUDGET");
            total+=n;
        }
        const auto parent=db.Root()/"artifacts";
        EnsurePrivateDirectory(parent);
        const auto final=parent/id;
        if(fs::exists(final))return VerifyResident(db,id);
        Require(fs::space(parent).available>total+1024*1024,"SEC_STORAGE_RESERVE");
        const auto staging=parent/("stage-"+Hex(RandomBytes(16)));
        EnsurePrivateDirectory(staging);
        try {
            for(const auto& f:e["body"]["files"].getValues()) {
                const auto rel=NativePath(Text(f,"path",1024));
                fs::create_directories((staging/rel).parent_path());
                const auto destination=staging/rel;
                Require(Stream(source/rel,UInt(f,"bytes",1ull<<44),&destination)==DigestField(f,"sha384"),
                "SEC_ARTIFACT_DIGEST");
            }
            // Publication is atomic; later execution still re-verifies bytes.
            Require(!fs::exists(final),"SEC_ARTIFACT_RACE");
            fs::rename(staging,final);
            Database::Transaction tx(db);
            db.Event("artifact-resident",id,Object());
            tx.Commit();
        }
        catch(...) {
            std::error_code ec;
            fs::remove_all(staging,ec);
            throw;
        }
        return VerifyResident(db,id);
    }
    std::string ResidentFrame(Database& db,const std::string& id,std::string_view input,uint64_t maximum) {
        Require(maximum<=16*1024*1024&&input.size()<=65536,"SEC_FRAME_LIMIT");
        auto root=VerifyResident(db,id);
        auto composition=db.Get(id);
        std::string out="BTX/MODELFRAME/1\n";
        Number(out,id.size());
        out+=id;
        Number(out,input.size());
        out+=input;
        Number(out,composition["body"]["files"].size());
        for(const auto& f:composition["body"]["files"].getValues()) {
            auto name=Text(f,"path",1024);
            auto size=UInt(f,"bytes",1ull<<44);
            Require(out.size()+name.size()+16<=maximum&&size<=maximum-out.size()-name.size()-16,
            "SEC_DESCRIPTOR_PROFILE_MODEL_TOO_LARGE");
            auto bytes=ReadFile(root/NativePath(name),size);
            Require(bytes.size()==size&&Hash(bytes)==DigestField(f,"sha384"),"SEC_RESIDENT_CHANGED");
            Number(out,name.size());
            out+=name;
            Number(out,size);
            out+=bytes;
        }
        return out;
    }
}
// namespace modelnet::security

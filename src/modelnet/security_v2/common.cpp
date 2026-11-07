// Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
#include <modelnet/security_v2/common.h>
#include <crypto/sha384.h>
extern "C" {
#include <libbitcoinpqc/ml_dsa.h>
}
#include <algorithm>
#include <cctype>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <aclapi.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#endif
namespace modelnet::security {

#ifdef _WIN32
    namespace {
        bool WindowsOwnerOnly(HANDLE handle)
        {
            PSECURITY_DESCRIPTOR descriptor=nullptr;
            PSID owner=nullptr;
            PACL acl=nullptr;
            const DWORD status=GetSecurityInfo(handle,SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&descriptor);
            struct Descriptor {PSECURITY_DESCRIPTOR value;~Descriptor(){if(value)LocalFree(value);}} saved{descriptor};
            if(status!=ERROR_SUCCESS||!owner||!acl)return false;
            HANDLE token=nullptr;
            if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;
            struct Token {HANDLE value;~Token(){CloseHandle(value);}} token_owner{token};
            DWORD size=0;
            GetTokenInformation(token,TokenUser,nullptr,0,&size);
            if(size==0||size>65536)return false;
            std::vector<unsigned char> bytes(size);
            if(!GetTokenInformation(token,TokenUser,bytes.data(),size,&size))return false;
            const PSID user=reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid;
            if(!EqualSid(owner,user))return false;
            for(DWORD index=0;index<acl->AceCount;++index) {
                void* raw=nullptr;
                if(!GetAce(acl,index,&raw))return false;
                const auto* header=static_cast<ACE_HEADER*>(raw);
                if(header->AceType==ACCESS_DENIED_ACE_TYPE)continue;
                if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE)return false;
                const auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
                PSID sid=const_cast<DWORD*>(&ace->SidStart);
                // OW applies to the object's owner, which was checked above.
                if(!IsValidSid(sid)||(!EqualSid(sid,user)&&!IsWellKnownSid(sid,WinLocalSystemSid)&&
                                     !IsWellKnownSid(sid,WinCreatorOwnerRightsSid)))return false;
            }
            return true;
        }
    }
#endif

    fs::path NativePath(std::string_view text) {
        return fs::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size()));
    }
    void Require(bool ok, const char* code) {
        if (!ok) throw Error(code);
    }
    int64_t NowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }
    std::string Hex(std::span<const unsigned char> bytes) {
        static constexpr char chars[] = "0123456789abcdef";
        std::string out(bytes.size()*2, '0');
        for (size_t i=0; i<bytes.size(); ++i) {
            out[2*i]=chars[bytes[i]>>4];
            out[2*i+1]=chars[bytes[i]&15];
        }
        return out;
    }
    Bytes Unhex(std::string_view s, size_t max_bytes) {
        Require(s.size()%2==0 && s.size()/2<=max_bytes,"SEC_HEX_LIMIT");
        auto nibble=[](char c)->unsigned char {
            if(c>='0'&&c<='9')return c-'0';
            if(c>='a'&&c<='f')return c-'a'+10;
            throw Error("SEC_HEX");
        };
        Bytes out(s.size()/2);
        for(size_t i=0; i<out.size(); ++i)out[i]=(nibble(s[2*i])<<4)|nibble(s[2*i+1]);
        return out;
    }
    bool IsHash(std::string_view s) {
        return s.size()==96 && std::all_of(s.begin(),s.end(),[](char c) {
            return (c>='0'&&c<='9')||(c>='a'&&c<='f');
        });
    }
    std::string Hash(std::span<const unsigned char> b) {
        std::array<unsigned char,48> h {
        };
        CSHA384().Write(b.data(),b.size()).Finalize(h.data());
        return Hex(h);
    }
    std::string Hash(std::string_view s) {
        return Hash(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()),s.size()));
    }
    namespace {
        void Append(Bytes& out,std::string_view value) {
            uint64_t n=value.size();
            for(int i=0; i<8; ++i)out.push_back(static_cast<unsigned char>(n>>(8*i)));
            out.insert(out.end(),value.begin(),value.end());
        }
        Bytes SigningMessage(std::string_view kind,const Json& body) {
            Bytes out;
            Append(out,"BTX/SecurityRecord/CanonicalJsonInteger/v1");
            Append(out,kind);
            Append(out,Canonical(body));
            return out;
        }
        bool ValidUtf8(std::string_view s) {
            for(size_t i=0; i<s.size(); ) {
                const auto a=static_cast<unsigned char>(s[i++]);
                if(a<128)continue;
                unsigned n;
                uint32_t v,min;
                if(a>=0xc2&&a<=0xdf) {
                    n=1;
                    v=a&31;
                    min=0x80;
                }
                else if(a>=0xe0&&a<=0xef) {
                    n=2;
                    v=a&15;
                    min=0x800;
                }
                else if(a>=0xf0&&a<=0xf4) {
                    n=3;
                    v=a&7;
                    min=0x10000;
                }
                else return false;
                if(i+n>s.size())return false;
                while(n--) {
                    const auto c=static_cast<unsigned char>(s[i++]);
                    if((c&0xc0)!=0x80)return false;
                    v=(v<<6)|(c&63);
                }
                if(v<min||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return false;
            }
            return true;
        }
        std::string Canon(const Json& v,unsigned depth,size_t& nodes) {
            Require(depth<=24 && ++nodes<=32768,"SEC_JSON_COMPLEXITY");
            if(v.isObject()) {
                Require(v.size()<=512,"SEC_JSON_FIELDS");
                std::map<std::string,const Json*> fields;
                const auto& keys=v.getKeys();
                const auto& values=v.getValues();
                for(size_t i=0; i<keys.size(); ++i) {
                    Require(ValidUtf8(keys[i])&&keys[i].size()<=256,"SEC_JSON_KEY");
                    Require(fields.emplace(keys[i],&values[i]).second,"SEC_JSON_DUPLICATE");
                }
                std::string out="{";
                for(const auto& [k,p]:fields) {
                    if(out.size()>1)out+=',';
                    out+=Json(k).write();
                    out+=':';
                    out+=Canon(*p,depth+1,nodes);
                }
                return out+'}';
            }
            if(v.isArray()) {
                Require(v.size()<=4096,"SEC_JSON_ARRAY");
                std::string out="[";
                for(const auto& x:v.getValues()) {
                    if(out.size()>1)out+=',';
                    out+=Canon(x,depth+1,nodes);
                }
                return out+']';
            }
            if(v.isNum()) {
                const auto s=v.getValStr();
                Require(!s.empty()&&s.size()<=20&&s!="-0","SEC_JSON_INTEGER");
                if(s[0]=='-') {
                    int64_t n=0;
                    auto r=std::from_chars(s.data(),s.data()+s.size(),n);
                    Require(r.ec==std::errc()&&r.ptr==s.data()+s.size(),"SEC_JSON_INTEGER");
                    return std::to_string(n);
                }
                uint64_t n=0;
                auto r=std::from_chars(s.data(),s.data()+s.size(),n);
                Require(r.ec==std::errc()&&r.ptr==s.data()+s.size(),"SEC_JSON_INTEGER");
                return std::to_string(n);
            }
            if(v.isStr())Require(v.get_str().size()<=MAX_RECORD&&ValidUtf8(v.get_str()),"SEC_JSON_STRING");
            Require(v.isStr()||v.isBool()||v.isNull(),"SEC_JSON_TYPE");
            return v.write();
        }
#ifndef _WIN32
        class Fd {
            public:int fd;
            explicit Fd(int f):fd(f) {
            }
            ~Fd() {
                if(fd>=0)close(fd);
            }
            Fd(const Fd&)=delete;
        };
        int OpenPath(const fs::path& path, int final_flags, mode_t mode=0600) {
            Require(path.is_absolute(),"SEC_ABSOLUTE_PATH");
            Fd current(open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));
            Require(current.fd>=0,"SEC_OPEN_ROOT");
            std::vector<std::string> parts;
            for(const auto& p:path.relative_path()) {
                const auto s=p.string();
                Require(!s.empty()&&s!="."&&s!="..","SEC_PATH");
                parts.push_back(s);
            }
            Require(!parts.empty(),"SEC_PATH");
            for(size_t i=0; i+1<parts.size(); ++i) {
                int next=openat(current.fd,parts[i].c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
                Require(next>=0,"SEC_PATH_COMPONENT");
                close(current.fd);
                current.fd=next;
            }
            return openat(current.fd,parts.back().c_str(),final_flags|O_NOFOLLOW|O_CLOEXEC,mode);
        }
#endif
    }
    std::string Canonical(const Json& v) {
        size_t nodes=0;
        auto out=Canon(v,0,nodes);
        Require(out.size()<=MAX_RECORD,"SEC_RECORD_LIMIT");
        return out;
    }
    Json Parse(std::string_view s,size_t limit) {
        Require(s.size()<=limit&&s.find('\0')==std::string_view::npos,"SEC_RECORD_LIMIT");
        Json v;
        Require(v.read(std::string(s)),"SEC_JSON_PARSE");
        (void)Canonical(v);
        return v;
    }
    std::string DomainHash(std::string_view domain,std::string_view payload) {
        Bytes data;
        Append(data,domain);
        Append(data,payload);
        return Hash(data);
    }
    Bytes RandomBytes(size_t n) {
        Require(n<=4096,"SEC_RANDOM_LIMIT");
        Bytes out(n);
#ifdef _WIN32
        Require(BCryptGenRandom(nullptr,out.data(),static_cast<ULONG>(n),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0,
        "SEC_ENTROPY");
#else
        Fd f(open("/dev/urandom",O_RDONLY|O_CLOEXEC));
        Require(f.fd>=0,"SEC_ENTROPY");
        size_t used=0;
        while(used<n) {
            ssize_t r=read(f.fd,out.data()+used,n-used);
            if(r<0&&errno==EINTR)continue;
            Require(r>0,"SEC_ENTROPY");
            used+=r;
        }
#endif
        return out;
    }
    void Cleanse(Bytes& b) noexcept {
        volatile unsigned char* p=b.data();
        for(size_t i=0; i<b.size(); ++i)p[i]=0;
        b.clear();
    }
    KeyPair GenerateKey() {
        KeyPair k {
            Bytes(PK_BYTES),Bytes(SK_BYTES)
        };
        auto entropy=RandomBytes(128);
        int r=ml_dsa_44_keygen(k.public_key.data(),k.secret_key.data(),entropy.data(),entropy.size());
        Cleanse(entropy);
        Require(r==0,"SEC_KEYGEN");
        return k;
    }
    std::string KeyId(std::span<const unsigned char> p) {
        Require(p.size()==PK_BYTES,"SEC_PUBLIC_KEY");
        return DomainHash("BTX/SecurityPrincipal/v1",std::string_view(reinterpret_cast<const char*>(p.data()),
        p.size()));
    }
    std::string Sign(std::string_view kind,const Json& body,std::span<const unsigned char> sk) {
        Require(sk.size()==SK_BYTES,"SEC_SECRET_KEY");
        const auto msg=SigningMessage(kind,body);
        Bytes sig(SIG_BYTES);
        size_t n=sig.size();
        Require(ml_dsa_44_sign(sig.data(),&n,msg.data(),msg.size(),sk.data())==0&&n==SIG_BYTES,"SEC_SIGNATURE");
        return Hex(sig);
    }
    bool Verify(std::string_view kind,const Json& body,std::span<const unsigned char> pk,std::span<const unsigned char> sig) {
        if(pk.size()!=PK_BYTES||sig.size()!=SIG_BYTES)return false;
        const auto msg=SigningMessage(kind,body);
        return ml_dsa_44_verify(sig.data(),sig.size(),msg.data(),msg.size(),pk.data())==0;
    }
    Json Object() {
        return Json(Json::VOBJ);
    }
    Json Array() {
        return Json(Json::VARR);
    }
    Json Strings(const std::vector<std::string>& values) {
        Json a=Array();
        for(const auto& s:values)a.push_back(s);
        return a;
    }
    std::vector<std::string> StringArray(const Json& v,size_t max_items) {
        Require(v.isArray()&&v.size()<=max_items,"SEC_STRING_ARRAY");
        std::set<std::string> seen;
        std::vector<std::string> out;
        for(const auto& x:v.getValues()) {
            Require(x.isStr()&&x.get_str().size()<=4096,"SEC_STRING_ARRAY");
            Require(seen.insert(x.get_str()).second,"SEC_DUPLICATE");
            out.push_back(x.get_str());
        }
        return out;
    }
    void Fields(const Json& v,std::initializer_list<std::string_view> required,std::initializer_list<std::string_view> optional) {
        Require(v.isObject(),"SEC_OBJECT");
        std::set<std::string> allowed;
        for(auto n:required) {
            Require(v.exists(std::string(n)),"SEC_MISSING_FIELD");
            allowed.emplace(n);
        }
        for(auto n:optional)allowed.emplace(n);
        std::set<std::string> seen;
        for(const auto& n:v.getKeys()) {
            Require(allowed.contains(n),"SEC_UNKNOWN_FIELD");
            Require(seen.insert(n).second,"SEC_JSON_DUPLICATE");
        }
    }
    std::string Text(const Json& v,std::string_view n,size_t max) {
        const auto& x=v[std::string(n)];
        Require(x.isStr()&&!x.get_str().empty()&&x.get_str().size()<=max,"SEC_TEXT");
        return x.get_str();
    }
    uint64_t UInt(const Json& v,std::string_view n,uint64_t max) {
        const auto& x=v[std::string(n)];
        Require(x.isNum(),"SEC_UINT");
        const auto s=x.getValStr();
        uint64_t out=0;
        auto r=std::from_chars(s.data(),s.data()+s.size(),out);
        Require(r.ec==std::errc()&&r.ptr==s.data()+s.size()&&out<=max,"SEC_UINT");
        return out;
    }
    bool Boolean(const Json& v,std::string_view n) {
        const auto& x=v[std::string(n)];
        Require(x.isBool(),"SEC_BOOLEAN");
        return x.get_bool();
    }
    std::string DigestField(const Json& v,std::string_view n) {
        auto s=Text(v,n,96);
        Require(IsHash(s),"SEC_DIGEST");
        return s;
    }
    Json Envelope(std::string_view kind,const Json& body) {
        Json out=Object();
        out.pushKV("schema","BTX/SecurityEnvelope/v1");
        out.pushKV("kind",std::string(kind));
        out.pushKV("body",body);
        out.pushKV("signatures",Array());
        return out;
    }
    void ValidateEnvelope(const Json& e) {
        Fields(e, {
            "schema","kind","body","signatures"
        });
        Require(Text(e,"schema")=="BTX/SecurityEnvelope/v1","SEC_ENVELOPE_VERSION");
        const auto kind=Text(e,"kind",32);
        static const std::set<std::string> kinds {
            "policy","composition","capsule","evaluation","challenge","channel","grant","revocation","peer","receipt",
            "lease","work","result","mandate","control","anchor","mesh","campaign"
        };
        Require(kinds.contains(kind),"SEC_RECORD_KIND");
        Require(e["body"].isObject()&&e["signatures"].isArray()&&e["signatures"].size()<=MAX_SIGNATURES,"SEC_ENVELOPE");
        for(const auto& s:e["signatures"].getValues()) {
            Fields(s, {
                "public_key","signature"
            });
            Require(Unhex(Text(s,"public_key",PK_BYTES*2),PK_BYTES).size()==PK_BYTES,"SEC_PUBLIC_KEY");
            Require(Unhex(Text(s,"signature",SIG_BYTES*2),SIG_BYTES).size()==SIG_BYTES,"SEC_SIGNATURE_SIZE");
        }
        (void)Canonical(e);
    }
    void AddSignature(Json& e,const KeyPair& k) {
        ValidateEnvelope(e);
        Json sigs=e["signatures"];
        Require(sigs.size()<MAX_SIGNATURES,"SEC_SIGNATURE_LIMIT");
        Json s=Object();
        s.pushKV("public_key",Hex(k.public_key));
        s.pushKV("signature",Sign(Text(e,"kind"),e["body"],k.secret_key));
        sigs.push_back(s);
        e.pushKV("signatures",sigs);
    }
    std::string RecordId(const Json& e) {
        ValidateEnvelope(e);
        Json m=Object();
        m.pushKV("kind",e["kind"]);
        m.pushKV("body",e["body"]);
        return DomainHash("BTX/SecurityObject/v1",Canonical(m));
    }
    bool IsPortablePath(std::string_view p) {
        if(p.empty()||p.size()>1024||p.front()=='/'||p.back()=='/')return false;
        size_t begin=0;
        while(begin<p.size()) {
            size_t end=p.find('/',begin);
            if(end==p.npos)end=p.size();
            auto s=p.substr(begin,end-begin);
            if(s.empty()||s=="."||s==".."||s.size()>240||s.back()=='.'||s.back()==' ')return false;
            for(unsigned char c:s)if(c<33||c>126||c=='\\'||c==':'||c=='*'||c=='?'||c=='"'||c=='<'||c=='>'||c=='|')return false;
            std::string u(s.substr(0,s.find('.')));
            std::transform(u.begin(),u.end(),u.begin(),[](unsigned char c) {
                return static_cast<char>(std::toupper(c));
            });
            if(u=="CON"||u=="PRN"||u=="AUX"||u=="NUL"||(u.size()==4&&(u.rfind("COM",0)==0||u.rfind("LPT",0)==0)&&u[3]>='0'&&u[3]<='9'))return false;
            begin=end+1;
        }
        return true;
    }
    bool IsCredentialPath(std::string_view p) {
        std::string s(p);
        std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        size_t b=0;
        while(b<s.size()) {
            size_t e=s.find('/',b);
            if(e==s.npos)e=s.size();
            auto x=s.substr(b,e-b);
            if(x==".ssh"||x==".aws"||x==".azure"||x==".gnupg"||x==".git"||x=="wallets"||x=="wallet.dat"||x==".cookie"||x==".env"||x.rfind(".env.",
            0)==0||x=="id_rsa"||x=="id_ed25519"||x=="id_ecdsa")return true;
            b=e+1;
        }
        return false;
    }
    std::string ReadFile(const fs::path& path,uint64_t limit,bool private_file) {
#ifdef _WIN32
        HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
        Require(h!=INVALID_HANDLE_VALUE,"SEC_FILE_OPEN");
        BY_HANDLE_FILE_INFORMATION info {
        };
        bool valid=GetFileInformationByHandle(h,&info)&&!(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))&&info.nNumberOfLinks==1;
        LARGE_INTEGER size {
        };
        valid=valid&&GetFileSizeEx(h,&size)&&size.QuadPart>=0&&static_cast<uint64_t>(size.QuadPart)<=limit;
        if(!valid) {
            CloseHandle(h);
            throw Error("SEC_FILE_TYPE_OR_LIMIT");
        }
        if(private_file&&!WindowsOwnerOnly(h)) {
            CloseHandle(h);throw Error("SEC_PRIVATE_FILE");
        }
        std::string out(static_cast<size_t>(size.QuadPart),'\0');
        size_t used=0;
        while(used<out.size()) {
            DWORD got=0;
            if(!::ReadFile(h,out.data()+used,static_cast<DWORD>(std::min<size_t>(out.size()-used,1<<20)),&got,nullptr)||got==0) {
                CloseHandle(h);
                throw Error("SEC_FILE_READ");
            }
            used+=got;
        }
        CloseHandle(h);
        return out;
#else
        Fd f(OpenPath(path,O_RDONLY));
        Require(f.fd>=0,"SEC_FILE_OPEN");
        struct stat s {
        };
        Require(fstat(f.fd,&s)==0&&S_ISREG(s.st_mode)&&s.st_nlink==1&&s.st_size>=0&&static_cast<uint64_t>(s.st_size)<=limit,
        "SEC_FILE_TYPE_OR_LIMIT");
        if(private_file)Require(s.st_uid==geteuid()&&(s.st_mode&077)==0,"SEC_PRIVATE_FILE");
        std::string out;
        out.reserve(static_cast<size_t>(s.st_size));
        std::array<char,8192> buf {
        };
        while(true) {
            ssize_t n=read(f.fd,buf.data(),buf.size());
            if(n<0&&errno==EINTR)continue;
            Require(n>=0,"SEC_FILE_READ");
            if(!n)break;
            Require(out.size()+static_cast<size_t>(n)<=limit,"SEC_FILE_LIMIT");
            out.append(buf.data(),n);
        }
        Require(out.size()==static_cast<size_t>(s.st_size),"SEC_FILE_CHANGED");
        return out;
#endif
    }
    void EnsurePrivateDirectory(const fs::path& path) {
        Require(path.is_absolute(),"SEC_ABSOLUTE_PATH");
        fs::path walk=path.root_path();
        for(const auto& part:path.relative_path()) {
            Require(part!=".."&&part!=".","SEC_PATH");
            walk/=part;
            std::error_code ec;
            auto st=fs::symlink_status(walk,ec);
            if(!fs::exists(st)) {
                Require(fs::create_directory(walk,ec)&&!ec,"SEC_DIRECTORY_CREATE");
#ifndef _WIN32
                Require(chmod(walk.c_str(),0700)==0,"SEC_DIRECTORY_MODE");
#else
                PSECURITY_DESCRIPTOR sd=nullptr;
                Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)(A;;FA;;;SY)",SDDL_REVISION_1,
                &sd,nullptr),"SEC_ACL");
                BOOL ok=SetFileSecurityW(walk.c_str(),DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd);
                LocalFree(sd);
                Require(ok,"SEC_ACL");
#endif
            }
            else Require(fs::is_directory(st)&&!fs::is_symlink(st),"SEC_DIRECTORY_TYPE");
        }
#ifndef _WIN32
        struct stat s {
        };
        Require(lstat(path.c_str(),&s)==0&&s.st_uid==geteuid()&&(s.st_mode&077)==0,"SEC_PRIVATE_DIRECTORY");
#else
        HANDLE directory=CreateFileW(path.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ,
            nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        Require(directory!=INVALID_HANDLE_VALUE,"SEC_PRIVATE_DIRECTORY");
        BY_HANDLE_FILE_INFORMATION info{};
        const bool valid=GetFileInformationByHandle(directory,&info)&&
            (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&
            !(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)&&WindowsOwnerOnly(directory);
        CloseHandle(directory);
        Require(valid,"SEC_PRIVATE_DIRECTORY");
#endif
    }
    void WritePrivate(const fs::path& path,std::string_view bytes,bool replace) {
        EnsurePrivateDirectory(path.parent_path());
        const auto temporary=path.parent_path()/(".new-"+Hex(RandomBytes(16)));
#ifdef _WIN32
        PSECURITY_DESCRIPTOR sd=nullptr;
        Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)(A;;FA;;;SY)",SDDL_REVISION_1,
        &sd,nullptr),"SEC_ACL");
        SECURITY_ATTRIBUTES sa {
            sizeof(sa),sd,FALSE
        };
        HANDLE h=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        LocalFree(sd);
        Require(h!=INVALID_HANDLE_VALUE,"SEC_FILE_CREATE");
        DWORD n=0;
        bool ok=bytes.size()<=MAXDWORD&&::WriteFile(h,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr)&&n==bytes.size()&&FlushFileBuffers(h);
        CloseHandle(h);
        if(!ok) {
            DeleteFileW(temporary.c_str());
            throw Error("SEC_FILE_WRITE");
        }
        if(!MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_WRITE_THROUGH|(replace?MOVEFILE_REPLACE_EXISTING:0))) {
            DeleteFileW(temporary.c_str());
            throw Error("SEC_FILE_COMMIT");
        }
#else
        Fd f(OpenPath(temporary,O_WRONLY|O_CREAT|O_EXCL));
        Require(f.fd>=0,"SEC_FILE_CREATE");
        try {
            size_t done=0;
            while(done<bytes.size()) {
                ssize_t n=write(f.fd,bytes.data()+done,bytes.size()-done);
                if(n<0&&errno==EINTR)continue;
                Require(n>0,"SEC_FILE_WRITE");
                done+=n;
            }
            Require(fsync(f.fd)==0,"SEC_FILE_SYNC");
            if(replace) {
                struct stat st {
                };
                if(lstat(path.c_str(),&st)==0)Require(S_ISREG(st.st_mode)&&st.st_nlink==1,"SEC_FILE_REPLACE");
                Require(rename(temporary.c_str(),path.c_str())==0,"SEC_FILE_COMMIT");
            }
            else {
                Require(link(temporary.c_str(),path.c_str())==0,"SEC_FILE_EXISTS");
                Require(unlink(temporary.c_str())==0,"SEC_FILE_COMMIT");
            }
            Fd d(OpenPath(path.parent_path(),O_RDONLY|O_DIRECTORY));
            Require(d.fd>=0&&fsync(d.fd)==0,"SEC_DIRECTORY_SYNC");
        }
        catch(...) {
            unlink(temporary.c_str());
            throw;
        }
#endif
    }
    Json Failure(std::string_view c) {
        Json j=Object();
        j.pushKV("ok",false);
        j.pushKV("error",std::string(c));
        j.pushKV("automatic_spend_atoms","0");
        return j;
    }
}
// namespace modelnet::security

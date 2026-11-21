// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SHARED_P2P_BROKER_H
#define BTX_SHARED_P2P_BROKER_H
#include <shared_p2p/core.h>
#include <atomic>
#include <cstring>
#include <functional>
#include <sstream>
#include <thread>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <cerrno>
#endif
namespace btx::p2p {
inline std::vector<unsigned char> Encode(const std::vector<std::string>& fields) {
    if(fields.size()>12)throw std::invalid_argument("broker field count");
    std::vector<unsigned char> out;auto put=[&out](std::uint32_t n){for(int i=3;i>=0;--i)out.push_back((n>>(i*8))&255);};
    put(fields.size());for(const auto& f:fields){if(f.size()>32768)throw std::invalid_argument("broker field size");put(f.size());out.insert(out.end(),f.begin(),f.end());}
    if(out.size()>65536)throw std::invalid_argument("broker frame size");return out;
}
inline std::vector<std::string> Decode(const std::vector<unsigned char>& bytes) {
    std::size_t p=0;auto get=[&](){if(p+4>bytes.size())throw std::runtime_error("short broker frame");std::uint32_t n=0;for(int j=0;j<4;++j)n=(n<<8)|bytes[p++];return n;};
    auto n=get();if(n>12)throw std::runtime_error("broker field count");std::vector<std::string> out;
    while(n--){auto len=get();if(len>32768||len>bytes.size()-p)throw std::runtime_error("broker field size");out.emplace_back(reinterpret_cast<const char*>(bytes.data()+p),len);p+=len;}
    if(p!=bytes.size())throw std::runtime_error("trailing broker data");return out;
}
inline std::uint64_t Unsigned(const std::string& text) {
    if(text.empty()||text.size()>20||text.find_first_not_of("0123456789")!=std::string::npos)throw std::runtime_error("invalid broker integer");
    return std::stoull(text);
}
#ifndef _WIN32
inline bool Wait(int fd,short event,int timeout=500) {
    pollfd p{fd,event,0};int n;do{n=::poll(&p,1,timeout);}while(n<0&&errno==EINTR);return n>0&&(p.revents&event);
}
inline bool Transfer(int fd,unsigned char* data,std::size_t len,bool write) {
    const auto deadline=NowMs()+750;
    while(len) {
        if(NowMs()>=deadline||!Wait(fd,write?POLLOUT:POLLIN,static_cast<int>(std::max<std::int64_t>(1,deadline-NowMs()))))return false;
#ifdef MSG_NOSIGNAL
        auto n = write ? ::send(fd,data,len,MSG_NOSIGNAL) : ::recv(fd,data,len,0);
#else
        auto n = write ? ::send(fd,data,len,0) : ::recv(fd,data,len,0);
#endif
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;if(n<=0)return false;data+=n;len-=n;
    }return true;
}
inline bool WriteFrame(int fd,const std::vector<std::string>& fields) {
    auto b=Encode(fields);unsigned char header[4];auto n=static_cast<std::uint32_t>(b.size());for(int i=0;i<4;++i)header[i]=(n>>(24-i*8))&255;
    return Transfer(fd,header,4,true)&&Transfer(fd,b.data(),b.size(),true);
}
inline std::vector<std::string> ReadFrame(int fd) {
    unsigned char header[4];if(!Transfer(fd,header,4,false))throw std::runtime_error("broker read timeout");
    std::uint32_t n=0;for(auto c:header)n=(n<<8)|c;if(n>65536||n<4)throw std::runtime_error("broker frame limit");
    std::vector<unsigned char> b(n);if(!Transfer(fd,b.data(),n,false))throw std::runtime_error("broker read timeout");return Decode(b);
}
inline bool SameOwner(int fd) {
#ifdef __linux__
    struct ucred cred{};socklen_t n=sizeof(cred);return ::getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&n)==0&&cred.uid==::getuid();
#elif defined(__APPLE__) || defined(__FreeBSD__)
    uid_t uid;gid_t gid;return ::getpeereid(fd,&uid,&gid)==0&&uid==::getuid();
#else
    return false;
#endif
}
inline bool SecureEqual(const std::string& a,const std::string& b) {if(a.size()!=b.size())return false;unsigned char d=0;for(std::size_t i=0;i<a.size();++i)d|=a[i]^b[i];return d==0;}
#endif

/** Owner-only, model-service-only IPC. The helper attests its own verified PQ1
 * session. This is explicitly a local trust boundary, not a remote proof.
 * Commands cannot invoke wallets, arbitrary RPC, filesystem paths or processes.
 */
class Broker {
    Core& core_;std::string endpoint_,token_;std::atomic<bool> stop_{false};std::thread thread_;
#ifndef _WIN32
    int listener_{-1};
    std::vector<std::string> Dispatch(const std::vector<std::string>& f) {
        if(f.size()<2||!SecureEqual(f[0],token_))return {"ERROR","AUTH"};
        if(f[1]=="open"&&f.size()==5) {
            auto id=core_.Admit(Service::ModelNet,f[2],f[3],f[4]);return id.empty()?std::vector<std::string>{"ERROR","ADMISSION"}:std::vector<std::string>{"OK",id};
        }
        if(f[1]=="charge"&&f.size()==5) {
            if(f[4]!="in"&&f[4]!="out")return {"ERROR","DIRECTION"};
            return core_.Charge(Service::ModelNet,f[2],Unsigned(f[3]),f[4]=="out")?std::vector<std::string>{"OK"}:std::vector<std::string>{"ERROR","BUDGET"};
        }
        if(f[1]=="close"&&f.size()==3){core_.Close(Service::ModelNet,f[2]);return {"OK"};}
        if(f[1]=="record"&&f.size()==6) {
            const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            bool ok=core_.PublishVerified(Service::ModelNet,Record{f[2],f[5],Unsigned(f[3]),static_cast<std::int64_t>(Unsigned(f[4]))},now);
            return {ok?"OK":"ERROR"};
        }
        if(f[1]=="learn"&&f.size()==5) {
            const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            return {core_.LearnRoute(Service::ModelNet,f[2],f[3],static_cast<std::int64_t>(Unsigned(f[4])),now)?"OK":"ERROR"};
        }
        if(f[1]=="routes"&&f.size()==3) {
            const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            auto routes=core_.Routes(Service::ModelNet,f[2],now);routes.insert(routes.begin(),"OK");return routes;
        }
        if(f[1]=="status"&&f.size()==2) {auto m=core_.Status(Service::ModelNet);return {"OK",core_.Network(),std::to_string(m.sessions),std::to_string(m.ingress_bytes),std::to_string(m.egress_bytes),std::to_string(m.rejected)};}
        return {"ERROR","METHOD"};
    }
    void Loop() {
        while(!stop_) {
            if(!Wait(listener_,POLLIN,100))continue;
            int fd=::accept(listener_,nullptr,nullptr);if(fd<0)continue;
            ::fcntl(fd,F_SETFD,FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
            int one=1;::setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
#endif
            if(SameOwner(fd))try{auto f=ReadFrame(fd);WriteFrame(fd,Dispatch(f));}catch(...){try{WriteFrame(fd,{"ERROR","FRAME"});}catch(...) {}}
            ::close(fd);
        }
    }
#endif
public:
    explicit Broker(Core& core):core_(core){}
    ~Broker(){Stop();}
    Broker(const Broker&)=delete;Broker& operator=(const Broker&)=delete;
    void Start(const std::string& endpoint,const std::string& token) {
        if(thread_.joinable())return;
        if(token.size()!=64||token.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::invalid_argument("broker requires 256-bit secret");
#ifndef _WIN32
        if(endpoint.size()>=sizeof(sockaddr_un{}.sun_path))throw std::runtime_error("shared P2P socket path too long");
        auto dir=std::filesystem::path(endpoint).parent_path();struct stat st{};
        if(::lstat(dir.c_str(),&st)||!S_ISDIR(st.st_mode)||st.st_uid!=::getuid()||(st.st_mode&0077))throw std::runtime_error("unsafe broker directory");
        if(std::filesystem::exists(endpoint)||std::filesystem::is_symlink(endpoint))throw std::runtime_error("refusing existing broker socket");
        listener_=::socket(AF_UNIX,SOCK_STREAM,0);if(listener_<0)throw std::runtime_error("broker socket failed");
        ::fcntl(listener_,F_SETFD,FD_CLOEXEC);sockaddr_un address{};address.sun_family=AF_UNIX;std::memcpy(address.sun_path,endpoint.c_str(),endpoint.size()+1);
        if(::bind(listener_,reinterpret_cast<sockaddr*>(&address),sizeof(address))||::chmod(endpoint.c_str(),0600)||::listen(listener_,16)) {::close(listener_);listener_=-1;::unlink(endpoint.c_str());throw std::runtime_error("broker bind failed");}
        endpoint_=endpoint;token_=token;stop_=false;thread_=std::thread([this]{Loop();});
#else
        (void)endpoint;throw std::runtime_error("supervised ModelNet IPC is not supported by this platform profile");
#endif
    }
    void Stop() {
#ifndef _WIN32
        stop_=true;if(thread_.joinable())thread_.join();if(listener_>=0){::close(listener_);listener_=-1;}
        if(!endpoint_.empty())::unlink(endpoint_.c_str());
#endif
        std::fill(token_.begin(),token_.end(),'\0');token_.clear();endpoint_.clear();
    }
};

class Client {
    std::string endpoint_,token_;mutable std::mutex mutex_;
public:
    void Configure(std::string endpoint,std::string token) {std::lock_guard<std::mutex> l(mutex_);endpoint_=std::move(endpoint);token_=std::move(token);}
    bool Configured()const {std::lock_guard<std::mutex> l(mutex_);return !endpoint_.empty();}
    std::vector<std::string> Call(std::vector<std::string> fields) {
        std::lock_guard<std::mutex> l(mutex_);
#ifndef _WIN32
        if(endpoint_.empty()||endpoint_.size()>=sizeof(sockaddr_un{}.sun_path))return {"ERROR","UNAVAILABLE"};
        int fd=::socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return {"ERROR","SOCKET"};
        ::fcntl(fd,F_SETFD,FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
        int one=1;::setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
#endif
        sockaddr_un address{};address.sun_family=AF_UNIX;std::memcpy(address.sun_path,endpoint_.c_str(),endpoint_.size()+1);
        if(::connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))||!SameOwner(fd)){::close(fd);return {"ERROR","CONNECT"};}
        try {fields.insert(fields.begin(),token_);if(!WriteFrame(fd,fields))throw std::runtime_error("broker write");auto result=ReadFrame(fd);::close(fd);return result;}
        catch(...){::close(fd);return {"ERROR","TRANSPORT"};}
#else
        (void)fields;return {"ERROR","UNSUPPORTED"};
#endif
    }
};
inline Client& ModelClient(){static Client client;return client;}
inline std::mutex& ModelSessionsMutex(){static std::mutex m;return m;}
inline std::map<int,std::string>& ModelSessions(){static std::map<int,std::string> s;return s;}
inline bool OpenModelSession(int fd,const std::string& pin,const std::string& group,bool strict_pq1) {
    if(!strict_pq1)return false;
    if(!ModelClient().Configured())return true; // standalone helper retains its original strict PQ1 limits
    auto response=ModelClient().Call({"open",pin,group,"PQ1/TLS1.3/MLKEM768/MLDSA44"});
    if(response.size()!=2||response[0]!="OK")return false;
    std::lock_guard<std::mutex> l(ModelSessionsMutex());auto old=ModelSessions().find(fd);
    if(old!=ModelSessions().end())ModelClient().Call({"close",old->second});ModelSessions()[fd]=response[1];return true;
}
inline bool ChargeModelSession(int fd,std::uint64_t bytes,bool outbound) {
    if(!ModelClient().Configured())return true;
    std::string id;{std::lock_guard<std::mutex> l(ModelSessionsMutex());auto i=ModelSessions().find(fd);if(i==ModelSessions().end())return false;id=i->second;}
    auto response=ModelClient().Call({"charge",id,std::to_string(bytes),outbound?"out":"in"});return !response.empty()&&response[0]=="OK";
}
inline void CloseModelSession(int fd) {
    std::string id;{std::lock_guard<std::mutex> l(ModelSessionsMutex());auto i=ModelSessions().find(fd);if(i==ModelSessions().end())return;id=i->second;ModelSessions().erase(i);}
    ModelClient().Call({"close",id});
}
}
#endif

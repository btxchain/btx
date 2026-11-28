#ifndef _WIN32
#include <sys/file.h>
#endif
#include <iterator>
#include <mutex>
#include <filesystem>
// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SHARED_P2P_RUNTIME_H
#define BTX_SHARED_P2P_RUNTIME_H
#include <shared_p2p/broker.h>
#include <memory>
namespace btx::p2p {

#ifndef _WIN32
// BTX_RUNTIME_LEASE_V1: protect a live broker's credential file before any rewrite.
inline int& RuntimeLeaseFd(){static int fd=-1;return fd;}
inline std::mutex& RuntimeLeaseMutex(){static std::mutex lock;return lock;}
inline bool AcquireRuntimeLease(const std::filesystem::path& dir){
    std::lock_guard<std::mutex> lock(RuntimeLeaseMutex());
    if(RuntimeLeaseFd()>=0)return false;
    const bool made=std::filesystem::create_directories(dir);
    if(made && ::chmod(dir.c_str(),0700)<0)throw std::runtime_error("Cannot protect shared runtime directory");
    struct stat st{};
    if(::lstat(dir.c_str(),&st)<0||!S_ISDIR(st.st_mode)||st.st_uid!=::getuid()||(st.st_mode&0077))
        throw std::runtime_error("Shared core directory must be owner-private before acquiring a runtime lease");
    auto path=dir/"broker.lock";
    int fd=::open(path.c_str(),O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)throw std::runtime_error("Cannot open private shared runtime lease");
    if(::fstat(fd,&st)<0||!S_ISREG(st.st_mode)||st.st_uid!=::getuid()||(st.st_mode&0077)||::flock(fd,LOCK_EX|LOCK_NB)<0){
        ::close(fd);throw std::runtime_error("Shared runtime directory is already in use or unsafe");
    }
    RuntimeLeaseFd()=fd;return true;
}
inline void ReleaseRuntimeLease(){
    std::lock_guard<std::mutex> lock(RuntimeLeaseMutex());
    if(RuntimeLeaseFd()>=0){::flock(RuntimeLeaseFd(),LOCK_UN);::close(RuntimeLeaseFd());RuntimeLeaseFd()=-1;}
}
#endif


inline std::mutex& RuntimeMutex(){static std::mutex m;return m;}
inline std::unique_ptr<Broker>& RuntimeBroker(){static std::unique_ptr<Broker> b;return b;}
inline std::string& RuntimeEndpoint(){static std::string s;return s;}
inline std::string Endpoint(){std::lock_guard<std::mutex> l(RuntimeMutex());return RuntimeEndpoint();}
inline void StartRuntimeUnleased(const std::string& network,const std::filesystem::path& directory,const std::string& random_token) {
    std::lock_guard<std::mutex> l(RuntimeMutex());if(RuntimeBroker())return;
    AuthoritativeCore().Start(network,directory);
#ifndef _WIN32
    const auto endpoint=(directory/"model-control.sock").string();
    const auto token_path=endpoint+".token";
    // Parent directory is owner-private. Never follow a pre-existing key link.
    if(std::filesystem::is_symlink(token_path))throw std::runtime_error("unsafe broker token path");
    int fd=::open(token_path.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)throw std::runtime_error("broker token file unavailable");
    if(::fchmod(fd,0600)||::write(fd,random_token.data(),random_token.size())!=static_cast<ssize_t>(random_token.size())||::fsync(fd)) {::close(fd);throw std::runtime_error("broker token write failed");}::close(fd);
    // Only reclaim an owned socket proven to have no listener. A live other
    // node is never replaced, even when it uses the same user account.
    struct stat st{};
    if(::lstat(endpoint.c_str(),&st)==0) {
        if(!S_ISSOCK(st.st_mode)||st.st_uid!=::getuid())throw std::runtime_error("unsafe stale broker socket");
        int probe=::socket(AF_UNIX,SOCK_STREAM,0);sockaddr_un address{};address.sun_family=AF_UNIX;
        if(endpoint.size()>=sizeof(address.sun_path)){if(probe>=0)::close(probe);throw std::runtime_error("broker socket path too long");}
        std::memcpy(address.sun_path,endpoint.c_str(),endpoint.size()+1);
        int rc = probe < 0 ? -1 : ::connect(probe,reinterpret_cast<sockaddr*>(&address),sizeof(address));int err=errno;if(probe>=0)::close(probe);
        if(rc==0||err!=ECONNREFUSED)throw std::runtime_error("broker socket is not safely reclaimable");
        if(::unlink(endpoint.c_str()))throw std::runtime_error("cannot reclaim stale broker socket");
    }
    auto broker=std::make_unique<Broker>(AuthoritativeCore());broker->Start(endpoint,random_token);
    RuntimeEndpoint()=endpoint;RuntimeBroker()=std::move(broker);
#else
    (void)random_token; // ModelNet helper spawning is unavailable in upstream Windows profile.
#endif
}
inline void StartRuntime(const std::string& network,const std::filesystem::path& directory,const std::string& random_token) {
#ifndef _WIN32
    const bool acquired=AcquireRuntimeLease(directory);
    try { StartRuntimeUnleased(network,directory,random_token); }
    catch(...) { if(acquired)ReleaseRuntimeLease();throw; }
#else
    StartRuntimeUnleased(network,directory,random_token);
#endif
}

inline void StopRuntimeUnleased(){std::lock_guard<std::mutex> l(RuntimeMutex());RuntimeBroker().reset();if(!RuntimeEndpoint().empty()){std::error_code ec;std::filesystem::remove(RuntimeEndpoint()+".token",ec);}RuntimeEndpoint().clear();}
inline void StopRuntime() {
    StopRuntimeUnleased();
#ifndef _WIN32
    ReleaseRuntimeLease();
#endif
}

inline void ConfigureModelClient(const std::string& endpoint) {
    if(endpoint.empty())return;
#ifndef _WIN32
    const auto path=endpoint+".token";struct stat st{};
    if(::lstat(path.c_str(),&st)||!S_ISREG(st.st_mode)||st.st_uid!=::getuid()||(st.st_mode&0077)||st.st_size!=64)throw std::runtime_error("invalid parent broker credential");
    auto dir=std::filesystem::path(path).parent_path();if(::lstat(dir.c_str(),&st)||!S_ISDIR(st.st_mode)||st.st_uid!=::getuid()||(st.st_mode&0077))throw std::runtime_error("unsafe parent broker directory");
    int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)throw std::runtime_error("broker credential unavailable");
    char data[64];auto n=::read(fd,data,sizeof(data));::close(fd);if(n!=64)throw std::runtime_error("short broker credential");
    std::string token(data,sizeof(data));std::fill(std::begin(data),std::end(data),'\0');
    ModelClient().Configure(endpoint,std::move(token));auto result=ModelClient().Call({"status"});
    if(result.empty()||result[0]!="OK")throw std::runtime_error("parent shared P2P core unavailable");
#else
    throw std::runtime_error("supervised shared P2P client unavailable on this platform");
#endif
}
}
#endif

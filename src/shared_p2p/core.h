// Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
#ifndef BTX_SHARED_P2P_CORE_H
#define BTX_SHARED_P2P_CORE_H
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace btx::p2p {
enum class Service : unsigned char { SwapNet=1, ModelNet=2 };
inline const char* Name(Service s) { return s==Service::SwapNet?"swapnet":"modelnet"; }
inline std::int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
struct Metrics {
    std::uint64_t admitted{0}, rejected{0}, ingress_bytes{0}, egress_bytes{0};
    std::size_t sessions{0}, records{0};
};
struct Record { std::string key, payload; std::uint64_t sequence; std::int64_t expires; };
struct Session {
    Service service; std::string identity, netgroup, assurance;
    std::int64_t touched_ms; std::uint64_t ingress{0},egress{0};
};
struct Bucket {
    std::uint64_t tokens{0}, capacity{0}, rate{0}; std::int64_t updated{0};
    bool Charge(std::uint64_t bytes,std::int64_t now) {
        if(now>updated) {
            const auto elapsed=static_cast<std::uint64_t>(std::min<std::int64_t>(now-updated,60000));
            tokens=std::min(capacity,tokens+elapsed*rate/1000);updated=now;
        }
        if(bytes>tokens)return false;tokens-=bytes;return true;
    }
};

/** One instance in btxd. A supervised ModelNet helper uses the typed broker;
 * it does not create a second authoritative singleton. No wallet/RPC callbacks
 * exist in this class. Signed-record verification belongs to service adapters.
 */
class Core {
    mutable std::mutex mutex_;
    std::string network_;
    std::filesystem::path directory_;
    std::map<std::string,Session> sessions_;
    std::map<Service,Metrics> metrics_;
    std::map<Service,Bucket> buckets_;
    std::map<Service,std::map<std::string,Record>> records_;
    std::uint64_t next_{0};
    bool running_{false};
    bool storage_failed_{false};
    struct Route {std::string hop;std::int64_t expires;};
    std::map<Service,std::map<std::string,std::vector<Route>>> routes_;
    static void Put32(std::ostream& s,std::uint32_t n) {
        for(int i=3;i>=0;--i)s.put(static_cast<char>((n>>(i*8))&255));
    }
    static std::uint32_t Get32(std::istream& s) {
        std::uint32_t n=0;for(int i=0;i<4;++i){int c=s.get();if(c<0)throw std::runtime_error("truncated cache");n=(n<<8)|static_cast<unsigned>(c);}return n;
    }
    static void PutString(std::ostream& s,const std::string& v) {Put32(s,static_cast<std::uint32_t>(v.size()));s.write(v.data(),v.size());}
    static std::string GetString(std::istream& s,std::size_t max) {
        auto n=Get32(s);if(n>max)throw std::runtime_error("cache field limit");std::string r(n,'\0');s.read(r.data(),n);if(!s)throw std::runtime_error("truncated cache");return r;
    }
    void SaveLocked(Service service,const std::map<std::string,Record>& records) {
        if(directory_.empty())return;
        const auto final=directory_/(std::string(Name(service))+".catalog");
        const auto temporary=directory_/(std::string(Name(service))+".catalog.new");
        if(std::filesystem::is_symlink(final)||std::filesystem::is_symlink(temporary))throw std::runtime_error("unsafe catalog path");
#ifndef _WIN32
        int fd=::open(temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        if(fd<0)throw std::runtime_error("catalog temporary path unavailable");::close(fd);
#endif
        try {
            std::ofstream file(temporary,std::ios::binary|std::ios::trunc);
            if(!file)throw std::runtime_error("catalog open failed");
            PutString(file,"BTX-SHARED-CATALOG-1");PutString(file,network_);Put32(file,static_cast<unsigned>(service));Put32(file,records.size());
            for(const auto& [key,r]:records) {PutString(file,key);PutString(file,std::to_string(r.sequence));PutString(file,std::to_string(r.expires));PutString(file,r.payload);}
            file.flush();if(!file)throw std::runtime_error("catalog write failed");file.close();
#ifndef _WIN32
            fd=::open(temporary.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)throw std::runtime_error("catalog fsync open failed");
            int rc=::fsync(fd);::close(fd);if(rc)throw std::runtime_error("catalog fsync failed");
#endif
            std::filesystem::rename(temporary,final);
#ifndef _WIN32
            fd=::open(directory_.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
            if(fd<0)throw std::runtime_error("catalog directory unavailable");int rc2=::fsync(fd);::close(fd);if(rc2)throw std::runtime_error("directory fsync failed");
#endif
        } catch(...) {std::error_code ec;std::filesystem::remove(temporary,ec);throw;}
    }
    void LoadLocked(Service service) {
        const auto path=directory_/(std::string(Name(service))+".catalog");
        if(!std::filesystem::exists(path))return;
        if(std::filesystem::is_symlink(path)||std::filesystem::file_size(path)>64*1024*1024)throw std::runtime_error("unsafe catalog file");
        std::ifstream file(path,std::ios::binary);
        if(GetString(file,32)!="BTX-SHARED-CATALOG-1"||GetString(file,64)!=network_||Get32(file)!=static_cast<unsigned>(service))throw std::runtime_error("catalog network or version mismatch");
        auto n=Get32(file);if(n>2048)throw std::runtime_error("catalog count limit");
        std::map<std::string,Record> loaded;
        while(n--) {
            auto key=GetString(file,512),seq=GetString(file,20),exp=GetString(file,20),payload=GetString(file,24576);
            if(seq.empty()||exp.empty()||seq.find_first_not_of("0123456789")!=std::string::npos||exp.find_first_not_of("0123456789")!=std::string::npos)throw std::runtime_error("invalid catalog integer");
            Record r{key,payload,std::stoull(seq),std::stoll(exp)};
            if(!loaded.emplace(key,std::move(r)).second)throw std::runtime_error("duplicate catalog key");
        }
        if(file.peek()!=EOF)throw std::runtime_error("trailing catalog bytes");
        records_[service]=std::move(loaded);
    }
public:
    void Start(const std::string& network,const std::filesystem::path& directory={}) {
        std::lock_guard<std::mutex> l(mutex_);
        if(network.size()!=64||network.find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::invalid_argument("exact chain genesis required");
        if(running_) {if(network_!=network)throw std::runtime_error("shared core already bound to another network");return;}
        network_=network;directory_=directory;
        if(!directory_.empty()) {
            if(std::filesystem::is_symlink(directory_))throw std::runtime_error("unsafe shared core directory");
            std::filesystem::create_directories(directory_);
#ifndef _WIN32
            struct stat st{};if(::lstat(directory_.c_str(),&st)||!S_ISDIR(st.st_mode)||st.st_uid!=::getuid())throw std::runtime_error("shared directory owner mismatch");
            if(::chmod(directory_.c_str(),0700))throw std::runtime_error("shared directory permission failure");
#endif
            LoadLocked(Service::SwapNet);LoadLocked(Service::ModelNet);
        }
        const auto now=NowMs();
        buckets_[Service::SwapNet]={1024*1024,1024*1024,512*1024,now};
        buckets_[Service::ModelNet]={32*1024*1024,32*1024*1024,16*1024*1024,now};
        running_=true;
    }
    bool Running()const {std::lock_guard<std::mutex> l(mutex_);return running_;}
    std::string Network()const {std::lock_guard<std::mutex> l(mutex_);return network_;}
    std::string Admit(Service service,const std::string& identity,const std::string& netgroup,const std::string& assurance,std::int64_t now=NowMs()) {
        std::lock_guard<std::mutex> l(mutex_);
        auto& m=metrics_[service];
        for(auto i=sessions_.begin();i!=sessions_.end();) {if(i->second.service==Service::ModelNet && now-i->second.touched_ms>180000)i=sessions_.erase(i);else ++i;}
        std::size_t count=0,group_count=0;
        for(const auto& [id,s]:sessions_)if(s.service==service){++count;if(s.netgroup==netgroup)++group_count;}
        if(!running_||identity.empty()||identity.size()>256||netgroup.size()>256||count>=128||group_count>=32||
           (service==Service::ModelNet&&assurance!="PQ1/TLS1.3/MLKEM768/MLDSA44")||
           (service==Service::SwapNet&&assurance!="BTX_VERSION_HANDSHAKE")) {++m.rejected;return {};}
        std::string id=std::string(Name(service))+":"+std::to_string(++next_);
        sessions_.emplace(id,Session{service,identity,netgroup,assurance,now});++m.admitted;return id;
    }
    bool Charge(Service service,const std::string& id,std::uint64_t bytes,bool outbound,std::int64_t now=NowMs()) {
        std::lock_guard<std::mutex> l(mutex_);auto& m=metrics_[service];auto i=sessions_.find(id);
        if(!running_||i==sessions_.end()||i->second.service!=service||bytes>32*1024*1024||!buckets_[service].Charge(bytes,now)) {++m.rejected;return false;}
        i->second.touched_ms=std::max(i->second.touched_ms,now);
        if(outbound){m.egress_bytes+=bytes;i->second.egress+=bytes;}else{m.ingress_bytes+=bytes;i->second.ingress+=bytes;}
        return true;
    }
    void Close(Service service,const std::string& id) {
        std::lock_guard<std::mutex> l(mutex_);auto i=sessions_.find(id);if(i!=sessions_.end()&&i->second.service==service)sessions_.erase(i);
    }
    bool PublishVerified(Service service,Record record,std::int64_t now_epoch) {
        std::lock_guard<std::mutex> l(mutex_);
        if(!running_||storage_failed_||record.key.empty()||record.key.size()>512||record.payload.size()>24576||record.sequence==0||record.expires<=now_epoch||record.expires>now_epoch+86400)return false;
        auto next=records_[service];
        for(auto i=next.begin();i!=next.end();) {if(i->second.expires<=now_epoch)i=next.erase(i);else ++i;}
        auto old=next.find(record.key);
        if(old!=next.end()) {
            if(record.sequence<old->second.sequence)return false;
            if(record.sequence==old->second.sequence)return record.payload==old->second.payload;
        } else if(next.size()>=2048)return false;
        next[record.key]=std::move(record);try{SaveLocked(service,next);}catch(...){storage_failed_=true;throw;}records_[service]=std::move(next);return true;
    }
    std::vector<Record> Page(Service service,const std::string& after,std::size_t limit,std::int64_t now_epoch)const {
        std::lock_guard<std::mutex> l(mutex_);std::vector<Record> out;if(limit>64)return out;
        auto m=records_.find(service);if(m==records_.end())return out;
        for(auto i=m->second.upper_bound(after);i!=m->second.end()&&out.size()<limit;++i)if(i->second.expires>now_epoch)out.push_back(i->second);return out;
    }
    bool LearnRoute(Service service,const std::string& identity,const std::string& hop,std::int64_t expires,std::int64_t now_epoch) {
        std::lock_guard<std::mutex> l(mutex_);
        if(!running_||identity.empty()||identity.size()>512||hop.empty()||hop.size()>300||expires<=now_epoch||expires>now_epoch+3600)return false;
        auto& table=routes_[service];
        if(!table.count(identity)&&table.size()>=8192)return false;
        auto& hops=table[identity];hops.erase(std::remove_if(hops.begin(),hops.end(),[&](const Route& r){return r.expires<=now_epoch;}),hops.end());
        for(auto& r:hops)if(r.hop==hop){r.expires=std::max(r.expires,expires);return true;}
        if(hops.size()>=4)return false;hops.push_back({hop,expires});return true;
    }
    std::vector<std::string> Routes(Service service,const std::string& identity,std::int64_t now_epoch)const {
        std::lock_guard<std::mutex> l(mutex_);std::vector<std::string> result;
        auto module=routes_.find(service);if(module==routes_.end())return result;
        auto item=module->second.find(identity);if(item==module->second.end())return result;
        for(const auto& route:item->second)if(route.expires>now_epoch)result.push_back(route.hop);
        return result;
    }
    Metrics Status(Service service)const {
        std::lock_guard<std::mutex> l(mutex_);Metrics m{};auto i=metrics_.find(service);if(i!=metrics_.end())m=i->second;
        for(const auto& [id,s]:sessions_)if(s.service==service)++m.sessions;
        auto r=records_.find(service);if(r!=records_.end())m.records=r->second.size();return m;
    }
};
inline Core& AuthoritativeCore(){static Core instance;return instance;}
}
#endif

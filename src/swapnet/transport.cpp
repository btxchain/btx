#include <swapnet/transport.h>
#include <algorithm>
#include <stdexcept>
namespace swapnet {
Transport::Transport(std::string network, bool enabled): m_network(std::move(network)),m_enabled(enabled) {
    if (m_network.size()!=64 || !std::all_of(m_network.begin(),m_network.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))
        throw std::invalid_argument("SwapNet requires an exact genesis hash");
}
bool Transport::KnownCommand(const std::string& c) {
    return c=="swhello"||c=="swget"||c=="swprov"||c=="swrfq"||c=="swquote"||c=="swterms"||c=="swreceipt";
}
void Transport::SetEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);m_enabled=enabled;
    if (!enabled) {m_peers.clear();m_in.clear();m_out.clear();}
}
void Transport::PeerReady(PeerId id,std::int64_t now) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_enabled||m_peers.count(id)||m_peers.size()>=MAX_PEERS||m_out.size()>=MAX_QUEUE)return;
    m_peers.emplace(id,Peer{false,16,now,now,0});
    m_out.push_back({id,"swhello","2:"+m_network});
}
void Transport::RetryHellos(std::int64_t now) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_enabled) return;
    for (auto& [id, peer] : m_peers) {
        if (peer.admitted || now - peer.hello_ms < 5000 || m_out.size() >= MAX_QUEUE) continue;
        m_out.push_back({id, "swhello", "2:" + m_network});
        peer.hello_ms = now;
    }
}
void Transport::PeerClosed(PeerId id) {
    std::lock_guard<std::mutex> lock(m_mutex);m_peers.erase(id);
    auto clean=[id](auto& q){q.erase(std::remove_if(q.begin(),q.end(),[id](const Frame& f){return f.peer==id;}),q.end());};
    clean(m_in);clean(m_out);
}
bool Transport::Receive(PeerId id,const std::string& command,const std::string& payload,std::int64_t now) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto fail=[this](){++m_rejected;return false;};
    auto it=m_peers.find(id);
    if (!m_enabled||it==m_peers.end()||!KnownCommand(command)||payload.empty()||payload.size()>MAX_FRAME)return fail();
    auto& p=it->second;
    // Clock rollback earns no credit. Charge before parsing or allocating a queue slot.
    const auto elapsed=std::max<std::int64_t>(0,now-p.last_ms);
    p.tokens=std::min(16.0,p.tokens+static_cast<double>(elapsed)/1000.0);
    p.last_ms=std::max(now,p.last_ms);
    const double cost=1.0+static_cast<double>(payload.size())/8192.0;
    if (p.tokens<cost) return fail();
    p.tokens-=cost;
    if (command=="swhello") {
        if (p.admitted||payload!="2:"+m_network)return fail();
        // The peer may have missed our initial hello while its runtime started.
        // Queue one reply before admission; duplicate hellos never generate replies.
        if (m_out.size()>=MAX_QUEUE)return fail();
        m_out.push_back({id,"swhello","2:"+m_network});
        p.admitted=true;return true;
    }
    if (!p.admitted||p.queued>=16||m_in.size()>=MAX_QUEUE)return fail();
    m_in.push_back({id,command,payload});++p.queued;return true;
}
bool Transport::Send(PeerId id,const std::string& command,const std::string& payload) {
    std::lock_guard<std::mutex> lock(m_mutex);auto it=m_peers.find(id);
    if (!m_enabled||it==m_peers.end()||!it->second.admitted||command=="swhello"||!KnownCommand(command)||payload.empty()||payload.size()>MAX_FRAME||m_out.size()>=MAX_QUEUE)return false;
    // The application relays only end-to-end authenticated bounded envelopes.
    if(std::count_if(m_out.begin(),m_out.end(),[id](const Frame& f){return f.peer==id;})>=32)return false;
    m_out.push_back({id,command,payload});return true;
}
std::optional<Frame> Transport::TakeInbound() {
    std::lock_guard<std::mutex> lock(m_mutex);if(m_in.empty())return {};
    auto f=std::move(m_in.front());m_in.pop_front();auto it=m_peers.find(f.peer);
    if(it!=m_peers.end()&&it->second.queued)--it->second.queued;
    return f;
}
std::optional<Frame> Transport::TakeOutbound() {
    std::lock_guard<std::mutex> lock(m_mutex);if(m_out.empty())return {};
    auto f=std::move(m_out.front());m_out.pop_front();return f;
}
std::optional<Frame> Transport::TakeOutboundForPeer(PeerId peer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it=std::find_if(m_out.begin(),m_out.end(),[peer](const Frame& f){return f.peer==peer;});
    if(it==m_out.end())return {};
    Frame result=std::move(*it);m_out.erase(it);return result;
}
std::vector<PeerId> Transport::AdmittedPeers() const {
    std::lock_guard<std::mutex> lock(m_mutex);std::vector<PeerId> result;
    for(const auto& [id,p]:m_peers)if(p.admitted)result.push_back(id);
    return result;
}
Stats Transport::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);std::size_t admitted=0;
    for(const auto& [id,p]:m_peers){(void)id;if(p.admitted)++admitted;}
    return {m_peers.size(),admitted,m_in.size(),m_out.size(),m_rejected,m_enabled};
}
}

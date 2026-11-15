// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/offer.h>

#include <modelnet/swarm_execnbhd/codes.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmExecNbhdOfferBook::Offer(const std::string& peer, int64_t rtt_ms, const std::string& trust_domain,
                                   bool authorized, bool compatible, std::string& err)
{
    if (peer.empty()) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_PEER);
    }
    if (rtt_ms < 0) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_RTT);
    }
    if (trust_domain.empty()) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_DOMAIN);
    }
    if (!authorized) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_NOT_AUTHORIZED);
    }
    if (!compatible) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_NOT_COMPAT);
    }
    if (m_peers.find(peer) != m_peers.end()) {
        return SwarmExecNbhdRefuse(err, SWARM_EXECNBHD_REPLAY);
    }
    SwarmExecNbhdRecord row;
    row.peer = peer;
    row.rtt_ms = rtt_ms;
    row.trust_domain = trust_domain;
    row.authorized = authorized;
    row.compatible = compatible;
    m_peers.emplace(peer, row);
    return SwarmExecNbhdAccept(err);
}

int64_t SwarmExecNbhdOfferBook::count() const
{
    return static_cast<int64_t>(m_peers.size());
}

bool SwarmExecNbhdOfferBook::contains(const std::string& peer) const
{
    return m_peers.find(peer) != m_peers.end();
}

std::string SwarmExecNbhdOfferBook::domain(const std::string& peer) const
{
    const auto found = m_peers.find(peer);
    if (found == m_peers.end()) {
        return {};
    }
    return found->second.trust_domain;
}

std::vector<SwarmExecNbhdRecord> SwarmExecNbhdOfferBook::Eligible() const
{
    std::vector<SwarmExecNbhdRecord> out;
    out.reserve(m_peers.size());
    for (const auto& item : m_peers) {
        if (!SwarmExecNbhdRecordAdmitted(item.second)) {
            continue;
        }
        out.push_back(item.second);
    }
    return out;
}

} // namespace modelnet

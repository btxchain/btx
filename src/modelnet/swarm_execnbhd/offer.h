// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_OFFER_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_OFFER_H

#include <modelnet/swarm_execnbhd/record.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Admitted peers waiting to be seated.
 * Offer does not seat. A refused offer leaves the book unchanged.
 * A replay keeps the first record, including its original rtt and domain.
 */
class SwarmExecNbhdOfferBook {
public:
    /**
     * First match wins: empty peer, rtt_ms below 0, empty trust domain,
     * authorized false, compatible false, then a peer id already stored.
     * Otherwise the peer is stored and err is cleared.
     */
    bool Offer(const std::string& peer, int64_t rtt_ms, const std::string& trust_domain, bool authorized,
               bool compatible, std::string& err);

    int64_t count() const;
    bool contains(const std::string& peer) const;
    std::string domain(const std::string& peer) const;
    /** Admitted records. Order is not seating order. */
    std::vector<SwarmExecNbhdRecord> Eligible() const;

private:
    std::map<std::string, SwarmExecNbhdRecord> m_peers;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_OFFER_H

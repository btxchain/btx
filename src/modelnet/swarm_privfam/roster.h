// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_ROSTER_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_ROSTER_H

#include <modelnet/swarm_privfam/record.h>

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Families stored by a successful Offer, keyed by family id.
 * store refuses an empty family, a public flag, and a family already
 * present. A refused store leaves the first privacy flag in place.
 * There is no erase and no method that marks a family published.
 */
class SwarmPrivFamRoster {
public:
    bool contains(const std::string& family) const;
    bool private_of(const std::string& family) const;
    std::size_t size() const;

    /**
     * Store family with its privacy flag.
     * Refuses an unusable record and a duplicate family. On refusal the
     * roster is unchanged.
     */
    bool store(const std::string& family, bool private_flag);

private:
    std::map<std::string, SwarmPrivFamRecord> m_families;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_ROSTER_H

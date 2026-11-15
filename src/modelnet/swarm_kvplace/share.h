// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_SHARE_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_SHARE_H

#include <modelnet/swarm_kvplace/offer.h>

#include <set>
#include <string>

namespace modelnet {

/**
 * Share records a fingerprint when both sides name that same fingerprint
 * and it is in the KV set. Different fingerprints, or either side not in
 * KV, are NOT_COMPAT and do not record a share.
 * Sharing does not move bytes.
 */
class SwarmKvPlaceShares {
public:
    bool Share(const SwarmKvPlaceBook& book, const std::string& left_fingerprint, const std::string& right_fingerprint,
               std::string& err);
    bool shared(const std::string& fingerprint) const;

private:
    std::set<std::string> m_shared;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_SHARE_H

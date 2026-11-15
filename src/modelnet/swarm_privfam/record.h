// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_RECORD_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_RECORD_H

#include <string>

namespace modelnet {

/**
 * One stored family and the privacy flag from the Offer that stored it.
 * Nothing here publishes the family, retains a seed, or connects.
 */
struct SwarmPrivFamRecord {
    std::string family;
    bool private_flag{false};
};

SwarmPrivFamRecord SwarmPrivFamMakeRecord(const std::string& family, bool private_flag);

/**
 * A record can be stored only when the family is non-empty and the
 * privacy flag is private.
 */
bool SwarmPrivFamRecordUsable(const SwarmPrivFamRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_RECORD_H

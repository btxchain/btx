// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_OFFER_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_OFFER_H

#include <modelnet/swarm_privfam/roster.h>

#include <string>

namespace modelnet {

/**
 * Offer family when private_flag is true and family is non-empty.
 * On success the family is stored as private and err is cleared.
 * On failure nothing new is stored and err is FAMILY, PUBLIC, or REPLAY.
 * A replay leaves the first privacy flag in place.
 * This does not publish the family, connect, or record a seed.
 */
bool SwarmPrivFamApply(SwarmPrivFamRoster& roster,
                        const std::string& family,
                        bool private_flag,
                        std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_OFFER_H

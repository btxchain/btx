// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_GATE_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_GATE_H

#include <modelnet/swarm_privfam/roster.h>

#include <string>

namespace modelnet {

/**
 * Refusal code for an Offer that must not store, or empty when the
 * family may be stored.
 * An empty family is FAMILY. A family already stored is REPLAY, and
 * that result wins over a public flag so the first privacy flag stays.
 * private_flag false on a family that is not stored is PUBLIC.
 * This function does not modify the roster.
 */
std::string SwarmPrivFamRefusal(const SwarmPrivFamRoster& roster,
                                const std::string& family,
                                bool private_flag);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_GATE_H

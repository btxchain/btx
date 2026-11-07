// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOUNFUNDED_H
#define BTX_MODELNET_SWARM_NOTNOUNFUNDED_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one pool. unfunded records that the pool does not
 * hold money. want_advertise asks this note to advertise the pool.
 *
 * advertised stays false and atoms stays 0 on every path. An unfunded
 * pool is not advertised as holding money.
 */
struct SwarmNotNoUnfunded {
    std::string pool_id;
    bool unfunded{false};
    bool want_advertise{false};
};

/**
 * Outcome of noting a pool. advertised stays false and atoms stays 0
 * on every path. An unfunded pool is not advertised as holding money.
 */
struct SwarmNotNoUnfundedResult {
    std::string code;
    bool advertised{false};
    int64_t atoms{0};
};

/**
 * Note a pool without advertising it as holding money. Order, first
 * match wins: an empty pool_id is POOL. unfunded true is NOT_HELD even
 * when want_advertise is false. want_advertise is HELD. Otherwise the
 * note is NOTED and err is clear. advertised stays false and atoms
 * stays 0 on every path. An unfunded pool is not advertised as holding
 * money.
 */
SwarmNotNoUnfundedResult SwarmNoteNotNoUnfunded(const SwarmNotNoUnfunded& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOUNFUNDED_H

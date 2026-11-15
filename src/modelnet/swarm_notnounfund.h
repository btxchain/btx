// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOUNFUND_H
#define BTX_MODELNET_SWARM_NOTNOUNFUND_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one pool. funded is whether this note records the
 * pool as funded. want_advertise asks this note to advertise the pool.
 *
 * advertised stays false and atoms stays 0 on every path. An unfunded
 * pool is not advertised as holding money.
 */
struct SwarmNotNoUnfund {
    std::string pool_id;
    bool funded{false};
    bool want_advertise{false};
};

/**
 * Outcome of noting a pool. advertised stays false and atoms stays 0
 * on every path. An unfunded pool is not advertised as holding money.
 */
struct SwarmNotNoUnfundResult {
    std::string code;
    bool advertised{false};
    int64_t atoms{0};
};

/**
 * Note a pool without advertising it as holding money. Order, first
 * match wins: an empty pool_id is POOL. funded false is UNFUNDED even
 * when want_advertise is false. want_advertise is UNFUNDED. Otherwise
 * the note is NOTED and err is clear. advertised stays false and atoms
 * stays 0 on every path. An unfunded pool is not advertised as holding
 * money.
 */
SwarmNotNoUnfundResult SwarmNoteNotNoUnfund(const SwarmNotNoUnfund& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOUNFUND_H

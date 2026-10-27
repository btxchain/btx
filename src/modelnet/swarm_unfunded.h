// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_UNFUNDED_H
#define BTX_MODELNET_SWARM_UNFUNDED_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Local inputs for a pool-balance advert note. An unfunded pool is not
 * advertised as holding money. A funded flag in this note still does not
 * create a spendable balance. Nothing is broadcast.
 */
struct SwarmPoolAdvert {
    std::string pool_id;
    bool funded{false};
    int64_t advertised_atoms{0};
    bool want_advertise_balance{false};
};

/**
 * Outcome of noting a pool advert. balance_advertised and spendable stay
 * false: this note does not advertise a balance or create a spendable one.
 */
struct SwarmPoolAdvertResult {
    bool balance_advertised{false};
    bool spendable{false};
    std::string code;
};

/**
 * Note a pool advert without advertising a balance.
 * An empty pool_id or advertised_atoms below zero yields POOL.
 * An unfunded pool yields UNFUNDED, even when want_advertise_balance is
 * true and advertised_atoms is large.
 * A request to advertise a balance yields HELD and clears err.
 * Otherwise the note is NOTED and err is cleared.
 * balance_advertised and spendable stay false on every return. An
 * unfunded pool is not advertised as holding money. A funded flag in
 * this note still does not create a spendable balance. Nothing is
 * broadcast.
 */
SwarmPoolAdvertResult SwarmNotePoolAdvert(const SwarmPoolAdvert& advert, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_UNFUNDED_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ONETEMPLATE_H
#define BTX_MODELNET_SWARM_ONETEMPLATE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one close template. positive_pools is the number of
 * pools with a positive balance. want_tx_per_pool asks this note to emit
 * one transaction per pool.
 *
 * One close template lists positive pool balances. It is not one
 * transaction per pool. This note does not build a transaction and does
 * not broadcast. tx_count stays 0 on every path. No hostnames or IPs
 * are used.
 */
struct SwarmCloseTemplateNote {
    int64_t positive_pools{0};
    bool want_tx_per_pool{false};
};

/**
 * Outcome of noting a close template. tx_count stays 0 on every path:
 * this note does not build a transaction and does not broadcast.
 */
struct SwarmCloseTemplateResult {
    int64_t tx_count{0};
    std::string code;
};

/**
 * Note a close template without building a transaction.
 * Order, first match wins: positive_pools below 0 is CLOSE.
 * want_tx_per_pool is ONE_TEMPLATE. positive_pools equal to 0 is EMPTY.
 * Otherwise the note is NOTED and err is clear.
 * tx_count stays 0 on every path. One close template lists positive pool
 * balances. It is not one transaction per pool and does not broadcast.
 */
SwarmCloseTemplateResult SwarmNoteCloseTemplate(const SwarmCloseTemplateNote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ONETEMPLATE_H

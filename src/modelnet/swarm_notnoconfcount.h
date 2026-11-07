// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCONFCOUNT_H
#define BTX_MODELNET_SWARM_NOTNOCONFCOUNT_H

#include <string>

namespace modelnet {

/**
 * A local note about one transaction. want_broadcast asks this note to
 * broadcast the transaction.
 *
 * broadcast stays false and l1_txs stays 0 on every path. A confirmation
 * count does not broadcast.
 */
struct SwarmNotNoConfCount {
    std::string tx_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting a transaction. broadcast stays false and l1_txs stays
 * 0 on every path. A confirmation count does not broadcast.
 */
struct SwarmNotNoConfCountResult {
    std::string code;
    bool broadcast{false};
    int l1_txs{0};
};

/**
 * Note a transaction without broadcasting it. Order, first match wins:
 * an empty tx_id is TX. want_broadcast is NOT_BROADCAST. Otherwise the
 * note is NOTED and err is cleared. broadcast stays false and l1_txs
 * stays 0 on every path. A confirmation count does not broadcast.
 */
SwarmNotNoConfCountResult SwarmNoteNotNoConfCount(const SwarmNotNoConfCount& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCONFCOUNT_H

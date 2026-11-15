// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTL1_H
#define BTX_MODELNET_SWARM_NOTL1_H

#include <string>

namespace modelnet {

/**
 * A local note about a pool payment. want_broadcast asks this note to
 * broadcast an L1 transaction.
 *
 * A pool payment does not create an L1 transaction, so broadcast stays
 * false and l1_txs stays 0 on every path.
 */
struct SwarmNotL1 {
    std::string payment_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting a pool payment. broadcast stays false and l1_txs
 * stays 0 on every path.
 */
struct SwarmNotL1Result {
    std::string code;
    bool broadcast{false};
    int l1_txs{0};
};

/**
 * Note that a pool payment does not create an L1 transaction.
 * Order, first match wins: an empty payment_id is PAYMENT. want_broadcast
 * is NOT_BROADCAST. Otherwise the note is NOTED and err is clear.
 * broadcast stays false and l1_txs stays 0 on every path. A pool payment
 * does not create an L1 transaction.
 */
SwarmNotL1Result SwarmNoteNotL1(const SwarmNotL1& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTL1_H

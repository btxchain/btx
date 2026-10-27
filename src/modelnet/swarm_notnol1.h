// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOL1_H
#define BTX_MODELNET_SWARM_NOTNOL1_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one clearing batch. want_broadcast asks this note to
 * broadcast an L1 transaction.
 *
 * A clearing batch broadcasts no L1 transaction, so broadcast stays false
 * and l1_txs stays 0 on every path.
 */
struct SwarmNotNoL1 {
    std::string batch_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting a clearing batch. broadcast stays false and l1_txs
 * stays 0 on every path. A clearing batch broadcasts no L1 transaction.
 */
struct SwarmNotNoL1Result {
    std::string code;
    bool broadcast{false};
    int64_t l1_txs{0};
};

/**
 * Note a clearing batch without broadcasting an L1 transaction.
 * Order, first match wins: an empty batch_id is BATCH. want_broadcast
 * is NOT_BROADCAST. Otherwise the note is NOTED and err is cleared.
 * broadcast stays false and l1_txs stays 0 on every path. A clearing
 * batch broadcasts no L1 transaction.
 */
SwarmNotNoL1Result SwarmNoteNotNoL1(const SwarmNotNoL1& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOL1_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLEARING_H
#define BTX_MODELNET_SWARM_NOTNOCLEARING_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one clearing batch. want_pay asks this note to pay.
 *
 * A clearing note pays nothing and creates no L1 transaction, so paid
 * stays false and l1_txs stays 0 on every path.
 */
struct SwarmNotNoClearing {
    std::string batch_id;
    bool want_pay{false};
};

/**
 * Outcome of noting a clearing request. paid stays false and l1_txs
 * stays 0 on every path. A clearing note pays nothing and creates no
 * L1 transaction.
 */
struct SwarmNotNoClearingResult {
    std::string code;
    bool paid{false};
    int64_t l1_txs{0};
};

/**
 * Note a clearing request without paying or creating an L1 transaction.
 * Order, first match wins: an empty batch_id is BATCH. want_pay is
 * NETTED. Otherwise the note is NOTED and err is cleared.
 * paid stays false and l1_txs stays 0 on every path.
 * A clearing note pays nothing and creates no L1 transaction.
 */
SwarmNotNoClearingResult SwarmNoteNotNoClearing(const SwarmNotNoClearing& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLEARING_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLEAR2_H
#define BTX_MODELNET_SWARM_NOTNOCLEAR2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one clearing batch. want_clear asks this note to pay.
 *
 * A clearing note pays nothing and creates no L1 transaction, so paid
 * stays false, atoms stays 0, and l1_txs stays 0 on every path.
 */
struct SwarmNotNoClear2 {
    std::string batch_id;
    bool want_clear{false};
};

/**
 * Outcome of noting a clearing request. paid stays false, atoms stays 0,
 * and l1_txs stays 0 on every path. A clearing note pays nothing and
 * creates no L1 transaction.
 */
struct SwarmNotNoClear2Result {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
    int l1_txs{0};
};

/**
 * Note a clearing request without paying or creating an L1 transaction.
 * Order, first match wins: an empty batch_id is BATCH. want_clear is
 * NOT_PAID. Otherwise the note is NOTED and err is cleared.
 * paid stays false, atoms stays 0, and l1_txs stays 0 on every path.
 * A clearing note pays nothing and creates no L1 transaction.
 */
SwarmNotNoClear2Result SwarmNoteNotNoClear2(const SwarmNotNoClear2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLEAR2_H

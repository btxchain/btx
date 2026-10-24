// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclear2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoClear2Result SwarmNoteNotNoClear2(const SwarmNotNoClear2& note, std::string& err)
{
    SwarmNotNoClear2Result result;
    result.paid = false;
    result.atoms = 0;
    result.l1_txs = 0;
    // A clearing note pays nothing and creates no L1 transaction.
    if (note.batch_id.empty()) {
        result.code = "BATCH";
        result.paid = false;
        result.atoms = 0;
        result.l1_txs = 0;
        err = "BATCH";
        return result;
    }
    if (note.want_clear) {
        result.code = "NOT_PAID";
        result.paid = false;
        result.atoms = 0;
        result.l1_txs = 0;
        err = "NOT_PAID";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    result.l1_txs = 0;
    err.clear();
    return result;
}

} // namespace modelnet

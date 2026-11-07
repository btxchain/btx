// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEQ_H
#define BTX_MODELNET_SWARM_NOTNOSEQ_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one clearing batch. batch_id names the batch.
 * want_step asks this note to take an extra sequence step.
 *
 * A clearing batch is one sequence step and creates no L1 transaction
 * per payment. stepped stays false and l1_txs stays 0 on every path.
 */
struct SwarmNotNoSeq {
    std::string batch_id;
    bool want_step{false};
};

/**
 * Outcome of noting a clearing batch. stepped stays false and l1_txs
 * stays 0 on every path. A clearing batch is one sequence step and
 * creates no L1 transaction per payment.
 */
struct SwarmNotNoSeqResult {
    std::string code;
    bool stepped{false};
    int64_t l1_txs{0};
};

/**
 * Note a clearing batch as one sequence step without an L1 transaction
 * per payment. Order, first match wins: an empty batch_id is BATCH.
 * want_step is ONE_STEP. Otherwise the note is NOTED and err is cleared.
 * stepped stays false and l1_txs stays 0 on every path.
 * A clearing batch is one sequence step and creates no L1 transaction
 * per payment.
 */
SwarmNotNoSeqResult SwarmNoteNotNoSeq(const SwarmNotNoSeq& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEQ_H

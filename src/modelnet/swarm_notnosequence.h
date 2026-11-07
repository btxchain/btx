// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEQUENCE_H
#define BTX_MODELNET_SWARM_NOTNOSEQUENCE_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one clearing batch. batch_id names the batch.
 * want_step asks this note to take an extra sequence step.
 *
 * A clearing batch takes no extra sequence step from this note.
 * stepped stays false and l1_txs stays 0 on every path.
 */
struct SwarmNotNoSequence {
    std::string batch_id;
    bool want_step{false};
};

/**
 * Outcome of noting a clearing batch. stepped stays false and l1_txs
 * stays 0 on every path. A clearing batch takes no extra sequence step
 * from this note.
 */
struct SwarmNotNoSequenceResult {
    std::string code;
    bool stepped{false};
    int64_t l1_txs{0};
};

/**
 * Note a clearing batch without an extra sequence step.
 * Order, first match wins: an empty batch_id is BATCH.
 * want_step is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * stepped stays false and l1_txs stays 0 on every path.
 * A clearing batch takes no extra sequence step from this note.
 */
SwarmNotNoSequenceResult SwarmNoteNotNoSequence(const SwarmNotNoSequence& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEQUENCE_H

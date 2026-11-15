// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SEQONCE_H
#define BTX_MODELNET_SWARM_SEQONCE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one sequence batch. payments is the number of
 * payments in the note. requested_sequence_steps is how many sequence
 * steps the note was asked to take.
 *
 * Many payments still use one sequence step. A request for one step per
 * payment is refused. This note does not advance a live channel and does
 * not broadcast. advanced stays false on every path. No hostnames or IPs
 * are used.
 */
struct SwarmSequenceBatch {
    int64_t payments{0};
    int64_t requested_sequence_steps{0};
};

/**
 * Outcome of noting a sequence batch. advanced stays false on every path:
 * this note does not advance a live channel and does not broadcast.
 */
struct SwarmSequenceBatchResult {
    bool advanced{false};
    std::string code;
};

/**
 * Note a sequence batch without advancing a live channel.
 * Order, first match wins: payments below 1 or requested_sequence_steps
 * below 1 is SEQUENCE. requested_sequence_steps other than 1 is ONCE.
 * Otherwise the note is NOTED and err is clear.
 * advanced stays false on every path. Many payments still use one sequence
 * step. A request for one step per payment is refused. This note does not
 * advance a live channel and does not broadcast.
 */
SwarmSequenceBatchResult SwarmNoteSequenceBatch(const SwarmSequenceBatch& batch, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SEQONCE_H

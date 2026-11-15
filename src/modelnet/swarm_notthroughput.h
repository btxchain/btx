// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTHROUGHPUT_H
#define BTX_MODELNET_SWARM_NOTTHROUGHPUT_H

#include <cstdint>
#include <string>

namespace modelnet {

/** A batch note that must not publish a throughput measurement. */
struct SwarmNotThroughput {
    std::string batch_id;
    bool want_publish{false};
};

/** Outcome of noting a batch without measuring throughput.
 *  published, payments_per_sec, and broadcast stay at their defaults.
 */
struct SwarmNotThroughputResult {
    std::string code;
    bool published{false};
    int64_t payments_per_sec{0};
    bool broadcast{false};
};

/** Note that a batch has no throughput measurement.
 *  Order, first match wins:
 *  1. An empty batch_id is BATCH. published is false, payments_per_sec is 0,
 *     broadcast is false, and err is BATCH.
 *  2. want_publish is UNMEASURED. published is false, payments_per_sec is 0,
 *     broadcast is false, and err is UNMEASURED.
 *  3. Otherwise the note is NOTED. published is false, payments_per_sec is 0,
 *     broadcast is false, and err is cleared.
 */
SwarmNotThroughputResult SwarmNoteNotThroughput(const SwarmNotThroughput& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTHROUGHPUT_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPCT_H
#define BTX_MODELNET_SWARM_NOTNOPCT_H

#include <string>

namespace modelnet {

/**
 * A local note that a run might publish latency percentiles.
 * want_publish asks this note to publish p50 and p95 figures.
 *
 * No latency percentile is published by this note. published stays false
 * and p50 and p95 stay 0 on every path.
 */
struct SwarmNotNoPct {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting that no latency percentile is published. published
 * stays false and p50 and p95 stay 0 on every path.
 */
struct SwarmNotNoPctResult {
    std::string code;
    bool published{false};
    int p50{0};
    int p95{0};
};

/**
 * Note that no latency percentile is published.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and p50 and p95 stay 0 on every path. No latency
 * percentile is published by this note.
 */
SwarmNotNoPctResult SwarmNoteNotNoPct(const SwarmNotNoPct& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPCT_H

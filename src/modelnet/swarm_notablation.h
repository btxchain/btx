// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTABLATION_H
#define BTX_MODELNET_SWARM_NOTABLATION_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about ablation for one run. want_publish asks this note to
 * publish an ablation multiplier.
 *
 * This note does not publish a multiplier. published stays false, and delta
 * stays 0, on every path.
 */
struct SwarmNotAblation {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting ablation. published stays false, and delta stays 0, on
 * every path. No multiplier is published.
 */
struct SwarmNotAblationResult {
    std::string code;
    bool published{false};
    int64_t delta{0};
};

/**
 * Note ablation without publishing a multiplier.
 * Order, first match wins: an empty run_id is RUN.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false, and delta stays 0, on every path.
 */
SwarmNotAblationResult SwarmNoteNotAblation(const SwarmNotAblation& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTABLATION_H

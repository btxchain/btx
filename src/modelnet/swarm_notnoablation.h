// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOABLATION_H
#define BTX_MODELNET_SWARM_NOTNOABLATION_H

#include <string>

namespace modelnet {

/**
 * A local unit note for one bench. want_publish asks this note to publish
 * an ablation measurement.
 *
 * A unit note is not an ablation measurement and publishes nothing.
 * published stays false, and qualified stays false, on every path.
 */
struct SwarmNotNoAblation {
    std::string bench_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a bench. published stays false, and qualified stays
 * false, on every path. A unit note is not an ablation measurement and
 * publishes nothing.
 */
struct SwarmNotNoAblationResult {
    std::string code;
    bool published{false};
    bool qualified{false};
};

/**
 * Note a bench without measuring ablation and without publishing.
 * Order, first match wins: an empty bench_id is BENCH.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is cleared.
 * published stays false, and qualified stays false, on every path.
 * A unit note is not an ablation measurement and publishes nothing.
 */
SwarmNotNoAblationResult SwarmNoteNotNoAblation(const SwarmNotNoAblation& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOABLATION_H

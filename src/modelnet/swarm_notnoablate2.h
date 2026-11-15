// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOABLATE2_H
#define BTX_MODELNET_SWARM_NOTNOABLATE2_H

#include <string>

namespace modelnet {

/**
 * A local note that a unit might publish an ablation.
 * run_id names the run. want_publish asks this note to publish one.
 *
 * A unit note publishes no ablation.
 * published stays false and rows stays 0 on every path.
 */
struct SwarmNotNoAblate2 {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unpublished ablation. published stays false
 * and rows stays 0 on every path: a unit note publishes no ablation.
 */
struct SwarmNotNoAblate2Result {
    std::string code;
    bool published{false};
    int rows{0};
};

/**
 * Note that no ablation is published.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and rows stays 0 on every path. A unit note
 * publishes no ablation.
 */
SwarmNotNoAblate2Result SwarmNoteNotNoAblate2(const SwarmNotNoAblate2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOABLATE2_H

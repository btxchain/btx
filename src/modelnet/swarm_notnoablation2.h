// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOABLATION2_H
#define BTX_MODELNET_SWARM_NOTNOABLATION2_H

#include <string>

namespace modelnet {

/**
 * A local note about one study. want_publish asks this note to publish a
 * multiplier.
 *
 * An ablation has not run and this note publishes no multiplier.
 * published stays false on every path.
 */
struct SwarmNotNoAblation2 {
    std::string study_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an ablation request. published stays false on
 * every path. An ablation has not run and this note publishes no multiplier.
 */
struct SwarmNotNoAblation2Result {
    std::string code;
    bool published{false};
};

/**
 * Note an ablation request without publishing a multiplier.
 * Order, first match wins: an empty study_id is STUDY.
 * want_publish is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * published stays false on every path.
 * An ablation has not run and this note publishes no multiplier.
 */
SwarmNotNoAblation2Result SwarmNoteNotNoAblation2(const SwarmNotNoAblation2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOABLATION2_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREPLAY_H
#define BTX_MODELNET_SWARM_NOTREPLAY_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate. quality_passed records a quality
 * graduation. want_exact_replay asks this note to admit ExactReplay.
 *
 * Quality graduation is not ExactReplay admission. This note does not
 * mine. admitted stays false on every path.
 */
struct SwarmNotReplay {
    std::string candidate_id;
    bool quality_passed{false};
    bool want_exact_replay{false};
};

/**
 * Outcome of noting a candidate. admitted stays false on every path:
 * a quality pass is noted as held and does not admit ExactReplay.
 */
struct SwarmNotReplayResult {
    std::string code;
    bool admitted{false};
};

/**
 * Note a candidate without admitting ExactReplay.
 * Order, first match wins: an empty candidate_id is REPLAY.
 * want_exact_replay is NOT_REPLAY, even when quality_passed is also true.
 * A quality pass is HELD and err is clear. Otherwise the note is NOTED
 * and err is clear. admitted stays false on every path. Quality
 * graduation is not ExactReplay admission. This note does not mine.
 */
SwarmNotReplayResult SwarmNoteNotReplay(const SwarmNotReplay& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREPLAY_H

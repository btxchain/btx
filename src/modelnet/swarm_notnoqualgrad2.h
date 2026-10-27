// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUALGRAD2_H
#define BTX_MODELNET_SWARM_NOTNOQUALGRAD2_H

#include <string>

namespace modelnet {

/**
 * A local note about one grade. quality records a quality graduation.
 * want_promote asks this note to promote a realm.
 *
 * A quality graduation is not a realm promotion.
 * promoted stays false on every path.
 */
struct SwarmNotNoQualGrad2 {
    std::string grade_id;
    bool quality{false};
    bool want_promote{false};
};

/**
 * Outcome of noting a quality graduation. promoted stays false on every
 * path. A quality graduation is not a realm promotion.
 */
struct SwarmNotNoQualGrad2Result {
    std::string code;
    bool promoted{false};
};

/**
 * Note a quality graduation without promoting a realm.
 * Order, first match wins: an empty grade_id is GRADE. quality is
 * NOT_PROMOTED even when want_promote is false. want_promote is HELD.
 * Otherwise the note is NOTED and err is cleared. promoted stays false
 * on every path. A quality graduation is not a realm promotion.
 */
SwarmNotNoQualGrad2Result SwarmNoteNotNoQualGrad2(const SwarmNotNoQualGrad2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUALGRAD2_H

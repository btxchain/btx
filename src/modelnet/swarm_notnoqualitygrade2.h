// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUALITYGRADE2_H
#define BTX_MODELNET_SWARM_NOTNOQUALITYGRADE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one grade. want_promote asks this note to promote
 * a realm.
 *
 * A quality grade does not promote a realm.
 * promoted stays false on every path.
 */
struct SwarmNotNoQualityGrade2 {
    std::string grade_id;
    bool want_promote{false};
};

/**
 * Outcome of noting a quality grade. promoted stays false on every path.
 * A quality grade does not promote a realm.
 */
struct SwarmNotNoQualityGrade2Result {
    std::string code;
    bool promoted{false};
};

/**
 * Note a quality grade without promoting a realm.
 * Order, first match wins: an empty grade_id is GRADE. want_promote is
 * HELD. Otherwise the note is NOTED and err is cleared. promoted stays
 * false on every path. A quality grade does not promote a realm.
 */
SwarmNotNoQualityGrade2Result SwarmNoteNotNoQualityGrade2(const SwarmNotNoQualityGrade2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUALITYGRADE2_H

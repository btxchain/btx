// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREALM_H
#define BTX_MODELNET_SWARM_NOTREALM_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate. quality_passed records a quality
 * graduation. want_realm_promote asks this note to promote a realm.
 *
 * Quality graduation is not realm promotion. This note does not promote
 * a realm. promoted stays false on every path.
 */
struct SwarmNotRealm {
    std::string candidate_id;
    bool quality_passed{false};
    bool want_realm_promote{false};
};

/**
 * Outcome of noting a candidate. promoted stays false on every path:
 * a quality pass is noted as held and does not promote a realm.
 */
struct SwarmNotRealmResult {
    std::string code;
    bool promoted{false};
};

/**
 * Note a candidate without promoting a realm.
 * Order, first match wins: an empty candidate_id is REALM.
 * want_realm_promote is NOT_REALM, even when quality_passed is also true.
 * A quality pass is HELD and err is clear. Otherwise the note is NOTED
 * and err is clear. promoted stays false on every path. Quality
 * graduation is not realm promotion.
 */
SwarmNotRealmResult SwarmNoteNotRealm(const SwarmNotRealm& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREALM_H

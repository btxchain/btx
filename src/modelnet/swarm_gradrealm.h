// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_GRADREALM_H
#define BTX_MODELNET_SWARM_GRADREALM_H

#include <string>

namespace modelnet {

/**
 * A local note about a quality graduation. candidate_id names the
 * candidate. quality_passed records that a quality check passed.
 * want_realm_promotion asks this note to promote a realm.
 * want_exact_replay asks this note to admit ExactReplay.
 *
 * Quality graduation is not realm promotion and not ExactReplay
 * admission. This note does not mine and does not broadcast. No
 * hostnames or IPs are used.
 */
struct SwarmGradRealm {
    std::string candidate_id;
    bool quality_passed{false};
    bool want_realm_promotion{false};
    bool want_exact_replay{false};
};

/**
 * Outcome of noting a quality graduation. realm_promoted and
 * exact_replay_admitted stay false on every path: this note does not
 * promote a realm and does not admit ExactReplay.
 */
struct SwarmGradRealmResult {
    bool realm_promoted{false};
    bool exact_replay_admitted{false};
    std::string code;
};

/**
 * Note a quality graduation without promoting a realm or admitting
 * ExactReplay.
 * Order, first match wins: an empty candidate_id is GRADUATE.
 * want_realm_promotion is REALM_REFUSED, including when quality_passed
 * and want_exact_replay are true. want_exact_replay is REPLAY_REFUSED,
 * including when quality_passed is true. quality_passed is HELD and err
 * is clear. Otherwise the note is NOTED and err is clear.
 * realm_promoted and exact_replay_admitted stay false. Quality
 * graduation is not realm promotion and not ExactReplay admission.
 * This note does not mine and does not broadcast.
 */
SwarmGradRealmResult SwarmNoteGraduationRealm(const SwarmGradRealm& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_GRADREALM_H

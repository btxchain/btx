// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTQUALREALM_H
#define BTX_MODELNET_SWARM_NOTQUALREALM_H

#include <string>

namespace modelnet {

/**
 * A local note about one evaluation. quality_pass records a quality pass.
 * want_promote asks this note to promote a realm.
 *
 * A quality pass is not realm promotion and not ExactReplay admission.
 * realm_promoted and admitted stay false on every path.
 */
struct SwarmNotQualRealm {
    std::string eval_id;
    bool quality_pass{false};
    bool want_promote{false};
};

/**
 * Outcome of noting an evaluation. realm_promoted and admitted stay false
 * on every path.
 */
struct SwarmNotQualRealmResult {
    std::string code;
    bool realm_promoted{false};
    bool admitted{false};
};

/**
 * Note an evaluation without promoting a realm or admitting ExactReplay.
 * Order, first match wins: an empty eval_id is EVAL. quality_pass is
 * NOT_REALM even when want_promote is false. want_promote is NOT_REALM.
 * Otherwise the note is NOTED and err is cleared. realm_promoted and
 * admitted stay false on every path. A quality pass is not realm
 * promotion and not ExactReplay admission.
 */
SwarmNotQualRealmResult SwarmNoteNotQualRealm(const SwarmNotQualRealm& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTQUALREALM_H

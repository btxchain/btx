// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREALM_H
#define BTX_MODELNET_SWARM_NOTNOREALM_H

#include <string>

namespace modelnet {

/**
 * A local note about one evaluation. quality_pass records a quality pass.
 * want_promote asks this note to promote a realm.
 *
 * A quality pass is not a realm promotion.
 * promoted and admitted stay false on every path.
 */
struct SwarmNotNoRealm {
    std::string eval_id;
    bool quality_pass{false};
    bool want_promote{false};
};

/**
 * Outcome of noting an evaluation. promoted and admitted stay false
 * on every path.
 */
struct SwarmNotNoRealmResult {
    std::string code;
    bool promoted{false};
    bool admitted{false};
};

/**
 * Note an evaluation without promoting a realm.
 * Order, first match wins: an empty eval_id is EVAL. quality_pass is
 * NOT_REALM even when want_promote is false. want_promote is NOT_REALM.
 * Otherwise the note is NOTED and err is cleared. promoted and admitted
 * stay false on every path. A quality pass is not a realm promotion.
 */
SwarmNotNoRealmResult SwarmNoteNotNoRealm(const SwarmNotNoRealm& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREALM_H

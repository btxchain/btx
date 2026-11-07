// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUAL2_H
#define BTX_MODELNET_SWARM_NOTNOQUAL2_H

#include <string>

namespace modelnet {

/**
 * A local note about one realm. graduated records a quality graduation.
 * want_promote asks this note to promote a realm.
 *
 * A quality graduation is not a realm promotion.
 * promoted and admitted stay false on every path.
 */
struct SwarmNotNoQual2 {
    std::string realm_id;
    bool graduated{false};
    bool want_promote{false};
};

/**
 * Outcome of noting a quality graduation. promoted and admitted stay false
 * on every path. A quality graduation is not a realm promotion.
 */
struct SwarmNotNoQual2Result {
    std::string code;
    bool promoted{false};
    bool admitted{false};
};

/**
 * Note a quality graduation without promoting a realm.
 * Order, first match wins: an empty realm_id is REALM. graduated is
 * NOT_PROMOTED even when want_promote is false. want_promote is HELD.
 * Otherwise the note is NOTED and err is cleared. promoted and admitted
 * stay false on every path. A quality graduation is not a realm promotion.
 */
SwarmNotNoQual2Result SwarmNoteNotNoQual2(const SwarmNotNoQual2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUAL2_H

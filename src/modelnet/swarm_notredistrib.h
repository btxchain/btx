// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREDISTRIB_H
#define BTX_MODELNET_SWARM_NOTREDISTRIB_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. want_redistribute asks this
 * note to grant redistribution.
 *
 * A download license is not a redistribution grant. granted stays false
 * and bytes_moved stays false on every path.
 */
struct SwarmNotRedistrib {
    std::string license_id;
    bool want_redistribute{false};
};

/**
 * Outcome of noting a download license. granted stays false and
 * bytes_moved stays false on every path. A download license is not a
 * redistribution grant.
 */
struct SwarmNotRedistribResult {
    std::string code;
    bool granted{false};
    bool bytes_moved{false};
};

/**
 * Note a download license without granting redistribution.
 * Order, first match wins: an empty license_id is LICENSE.
 * want_redistribute is NOT_GRANT. Otherwise the note is NOTED and err
 * is clear. granted stays false and bytes_moved stays false on every
 * path. A download license is not a redistribution grant.
 */
SwarmNotRedistribResult SwarmNoteNotRedistrib(const SwarmNotRedistrib& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREDISTRIB_H

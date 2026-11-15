// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREDIST2_H
#define BTX_MODELNET_SWARM_NOTNOREDIST2_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. download records that a
 * license was obtained. want_grant asks this note to grant redistribution.
 *
 * A download license is not a redistribution grant. granted stays false
 * on every path.
 */
struct SwarmNotNoRedist2 {
    std::string license_id;
    bool download{false};
    bool want_grant{false};
};

/**
 * Outcome of noting a download license. granted stays false on every path.
 * A download license is not a redistribution grant.
 */
struct SwarmNotNoRedist2Result {
    std::string code;
    bool granted{false};
};

/**
 * Note a download license without granting redistribution.
 * Order, first match wins: an empty license_id is LICENSE. download is
 * NOT_REDIST even when want_grant is false. want_grant is HELD. Otherwise
 * the note is NOTED and err is cleared. granted stays false on every path.
 * A download license is not a redistribution grant.
 */
SwarmNotNoRedist2Result SwarmNoteNotNoRedist2(const SwarmNotNoRedist2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREDIST2_H

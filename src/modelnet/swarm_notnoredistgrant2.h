// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREDISTGRANT2_H
#define BTX_MODELNET_SWARM_NOTNOREDISTGRANT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. download marks a license that
 * permits download. want_share asks this note to treat a download license
 * as a redistribution grant.
 *
 * A download license is not a redistribution grant, so shared stays false
 * on every path.
 */
struct SwarmNotNoRedistGrant2 {
    std::string license_id;
    bool download{false};
    bool want_share{false};
};

/**
 * Outcome of noting a download license. shared stays false on every path:
 * a download license is not a redistribution grant.
 */
struct SwarmNotNoRedistGrant2Result {
    std::string code;
    bool shared{false};
};

/**
 * Note a download license without granting redistribution.
 * Order, first match wins: an empty license_id is LICENSE. download is
 * NOT_SHARED even when want_share is false. want_share is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * shared stays false on every path. A download license is not a
 * redistribution grant.
 */
SwarmNotNoRedistGrant2Result SwarmNoteNotNoRedistGrant2(const SwarmNotNoRedistGrant2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREDISTGRANT2_H

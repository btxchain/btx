// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODOWNLICGRANT2_H
#define BTX_MODELNET_SWARM_NOTNODOWNLICGRANT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. download marks a license that
 * permits download. want_train asks this note to treat a download license
 * as a training grant.
 *
 * A download license is not a training grant, so granted stays false on
 * every path.
 */
struct SwarmNotNoDownLicGrant2 {
    std::string license_id;
    bool download{false};
    bool want_train{false};
};

/**
 * Outcome of noting a download license. granted stays false on every path:
 * a download license is not a training grant.
 */
struct SwarmNotNoDownLicGrant2Result {
    std::string code;
    bool granted{false};
};

/**
 * Note a download license without granting training.
 * Order, first match wins: an empty license_id is LICENSE. download is
 * NOT_GRANTED even when want_train is false. want_train is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * granted stays false on every path. A download license is not a training
 * grant.
 */
SwarmNotNoDownLicGrant2Result SwarmNoteNotNoDownLicGrant2(const SwarmNotNoDownLicGrant2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODOWNLICGRANT2_H

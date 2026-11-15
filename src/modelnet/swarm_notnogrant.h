// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGRANT_H
#define BTX_MODELNET_SWARM_NOTNOGRANT_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. want_train asks this note to
 * treat a download license as a training grant.
 *
 * A download license is not a training grant. granted and trained stay
 * false on every path.
 */
struct SwarmNotNoGrant {
    std::string license_id;
    bool want_train{false};
};

/**
 * Outcome of noting a download license. granted and trained stay false on
 * every path: a download license is not a training grant.
 */
struct SwarmNotNoGrantResult {
    std::string code;
    bool granted{false};
    bool trained{false};
};

/**
 * Note a download license without granting training.
 * Order, first match wins: an empty license_id is LICENSE. want_train is
 * NOT_GRANT. Otherwise the note is NOTED and err is cleared.
 * granted and trained stay false on every path.
 * A download license is not a training grant.
 */
SwarmNotNoGrantResult SwarmNoteNotNoGrant(const SwarmNotNoGrant& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGRANT_H

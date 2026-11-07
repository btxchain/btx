// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOID_H
#define BTX_MODELNET_SWARM_NOTNOID_H

#include <string>

namespace modelnet {

/**
 * A local note about one identity. want_grant asks this note to grant a
 * license.
 *
 * An identity note grants no license and moves no bytes. granted stays
 * false and bytes_moved stays false on every path.
 */
struct SwarmNotNoId {
    std::string identity_id;
    bool want_grant{false};
};

/**
 * Outcome of noting an identity. granted stays false and bytes_moved
 * stays false on every path. An identity note grants no license and
 * moves no bytes.
 */
struct SwarmNotNoIdResult {
    std::string code;
    bool granted{false};
    bool bytes_moved{false};
};

/**
 * Note an identity without granting a license.
 * Order, first match wins: an empty identity_id is IDENTITY.
 * want_grant is NOT_GRANT. Otherwise the note is NOTED and err
 * is clear. granted stays false and bytes_moved stays false on every
 * path. An identity note grants no license and moves no bytes.
 */
SwarmNotNoIdResult SwarmNoteNotNoId(const SwarmNotNoId& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOID_H

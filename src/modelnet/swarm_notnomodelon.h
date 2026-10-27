// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMODELON_H
#define BTX_MODELNET_SWARM_NOTNOMODELON_H

#include <string>

namespace modelnet {

/**
 * A local note about ModelNet for one node. want_disable asks this note
 * to turn ModelNet off.
 *
 * ModelNet stays on by default. This note does not stop it, so disabled
 * and stopped stay false on every path.
 */
struct SwarmNotNoModelOn {
    std::string node_id;
    bool want_disable{false};
};

/**
 * Outcome of noting ModelNet. disabled and stopped stay false on every
 * path: this note does not stop it.
 */
struct SwarmNotNoModelOnResult {
    std::string code;
    bool disabled{false};
    bool stopped{false};
};

/**
 * Note ModelNet without stopping it.
 * Order, first match wins: an empty node_id is NODE. want_disable is
 * HELD. Otherwise the note is NOTED and err is cleared. disabled and
 * stopped stay false on every path. ModelNet stays on by default. This
 * note does not stop it.
 */
SwarmNotNoModelOnResult SwarmNoteNotNoModelOn(const SwarmNotNoModelOn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMODELON_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMODELNET2_H
#define BTX_MODELNET_SWARM_NOTNOMODELNET2_H

#include <string>

namespace modelnet {

/**
 * A local note about ModelNet for one node. want_disable asks this note
 * to turn ModelNet off.
 *
 * ModelNet stays on by default. This note does not turn it off, so
 * disabled stays false on every path.
 */
struct SwarmNotNoModelNet2 {
    std::string node_id;
    bool want_disable{false};
};

/**
 * Outcome of noting ModelNet. disabled stays false on every path: this
 * note does not turn it off.
 */
struct SwarmNotNoModelNet2Result {
    std::string code;
    bool disabled{false};
};

/**
 * Note ModelNet without turning it off.
 * Order, first match wins: an empty node_id is NODE. want_disable is
 * HELD. Otherwise the note is NOTED and err is cleared. disabled stays
 * false on every path. ModelNet stays on by default.
 */
SwarmNotNoModelNet2Result SwarmNoteNotNoModelNet2(const SwarmNotNoModelNet2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMODELNET2_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEED2_H
#define BTX_MODELNET_SWARM_NOTNOSEED2_H

#include <string>

namespace modelnet {

/**
 * A local note about public seeding for one node. want_disable asks this
 * note to disable it.
 *
 * Public seeding stays on. This note does not disable it, so disabled
 * stays false on every path.
 */
struct SwarmNotNoSeed2 {
    std::string node_id;
    bool want_disable{false};
};

/**
 * Outcome of noting public seeding. disabled stays false on every path.
 * Public seeding stays on.
 */
struct SwarmNotNoSeed2Result {
    std::string code;
    bool disabled{false};
};

/**
 * Note public seeding without disabling it.
 * Order, first match wins: an empty node_id is NODE. want_disable is
 * HELD. Otherwise the note is NOTED and err is cleared. disabled stays
 * false on every path. Public seeding stays on.
 */
SwarmNotNoSeed2Result SwarmNoteNotNoSeed2(const SwarmNotNoSeed2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEED2_H

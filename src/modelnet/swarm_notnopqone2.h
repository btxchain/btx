// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPQONE2_H
#define BTX_MODELNET_SWARM_NOTNOPQONE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one payment mesh. want_add asks this note to add
 * another mesh. The payment mesh stays one. added stays false on every path.
 */
struct SwarmNotNoPqOne2 {
    std::string mesh_id;
    bool want_add{false};
};

/**
 * Outcome of noting one payment mesh. added stays false on every path.
 * The payment mesh stays one.
 */
struct SwarmNotNoPqOne2Result {
    std::string code;
    bool added{false};
};

/**
 * Note one payment mesh without adding another.
 * Order, first match wins: an empty mesh_id is MESH. want_add is HELD.
 * Otherwise the note is NOTED and err is clear. added stays false on every
 * path. The payment mesh stays one.
 */
SwarmNotNoPqOne2Result SwarmNoteNotNoPqOne2(const SwarmNotNoPqOne2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPQONE2_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTHASHLEAF_H
#define BTX_MODELNET_SWARM_NOTHASHLEAF_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_build asks this note to build a
 * contributor hashlock leaf.
 *
 * A contributor hashlock leaf is not built or broadcast by this note.
 * built and broadcast stay false on every path.
 */
struct SwarmNotHashLeaf {
    std::string channel_id;
    bool want_build{false};
};

/**
 * Outcome of noting a contributor hashlock leaf. built and broadcast
 * stay false on every path. A contributor hashlock leaf is not built
 * or broadcast by this note.
 */
struct SwarmNotHashLeafResult {
    std::string code;
    bool built{false};
    bool broadcast{false};
};

/**
 * Note a contributor hashlock leaf without building or broadcasting it.
 * Order, first match wins: an empty channel_id is CHANNEL. want_build
 * is NOT_BUILT. Otherwise the note is NOTED and err is cleared. built
 * and broadcast stay false on every path. A contributor hashlock leaf
 * is not built or broadcast by this note.
 */
SwarmNotHashLeafResult SwarmNoteNotHashLeaf(const SwarmNotHashLeaf& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTHASHLEAF_H

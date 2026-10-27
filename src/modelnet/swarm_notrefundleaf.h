// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREFUNDLEAF_H
#define BTX_MODELNET_SWARM_NOTREFUNDLEAF_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_refund asks this note to build a
 * refund leaf.
 *
 * A refund leaf is not built or broadcast by this note. built and
 * broadcast stay false on every path.
 */
struct SwarmNotRefundLeaf {
    std::string channel_id;
    bool want_refund{false};
};

/**
 * Outcome of noting a refund leaf. built and broadcast stay false on
 * every path. A refund leaf is not built or broadcast by this note.
 */
struct SwarmNotRefundLeafResult {
    std::string code;
    bool built{false};
    bool broadcast{false};
};

/**
 * Note a refund without building or broadcasting a leaf.
 * Order, first match wins: an empty channel_id is CHANNEL. want_refund
 * is HELD. Otherwise the note is NOTED and err is clear. built and
 * broadcast stay false on every path. A refund leaf is not built or
 * broadcast by this note.
 */
SwarmNotRefundLeafResult SwarmNoteNotRefundLeaf(const SwarmNotRefundLeaf& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREFUNDLEAF_H

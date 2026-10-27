// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREFUNDLEAF2_H
#define BTX_MODELNET_SWARM_NOTNOREFUNDLEAF2_H

#include <string>

namespace modelnet {

/**
 * A local note about one contract. want_build asks this note to build
 * a refund leaf.
 *
 * A contributor HTLC note builds no refund leaf. built stays false on
 * every path.
 */
struct SwarmNotNoRefundLeaf2 {
    std::string contract_id;
    bool want_build{false};
};

/**
 * Outcome of noting a contributor HTLC. built stays false on every
 * path. A contributor HTLC note builds no refund leaf.
 */
struct SwarmNotNoRefundLeaf2Result {
    std::string code;
    bool built{false};
};

/**
 * Note a contributor HTLC without building a refund leaf.
 * Order, first match wins: an empty contract_id is CONTRACT. want_build
 * is HELD. Otherwise the note is NOTED and err is cleared. built stays
 * false on every path. A contributor HTLC note builds no refund leaf.
 */
SwarmNotNoRefundLeaf2Result SwarmNoteNotNoRefundLeaf2(const SwarmNotNoRefundLeaf2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREFUNDLEAF2_H

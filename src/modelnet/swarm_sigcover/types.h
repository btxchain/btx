// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_TYPES_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_TYPES_H

namespace modelnet {

/**
 * One id's signature-cover row.
 * outputs_covered becomes true when Cover stores a description that covered
 * outputs. No writer sets it back to false.
 * preimage_described becomes true when Preimage stores a 32-byte length.
 * No writer stores another length, and no writer clears a stored description.
 * The row has no key, no signature bit, no claim bit, and no penalty bit.
 */
struct SwarmSigCoverRecord {
    bool outputs_covered{false};
    bool preimage_described{false};
};

/**
 * A decision from Cover or Preimage.
 * accepted is true only when a one-way mark should be written.
 * mark_covered and mark_preimage request a set-to-true.
 * A refused plan leaves any stored cover and any stored preimage in place.
 */
struct SwarmSigCoverPlan {
    bool accepted{false};
    bool mark_covered{false};
    bool mark_preimage{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_TYPES_H

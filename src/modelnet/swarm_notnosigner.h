// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIGNER_H
#define BTX_MODELNET_SWARM_NOTNOSIGNER_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_start asks this note to start a
 * signer.
 *
 * This note does not start a signer or sign a block. started and
 * signed_block stay false on every path.
 */
struct SwarmNotNoSigner {
    std::string node_id;
    bool want_start{false};
};

/**
 * Outcome of noting a node. started and signed_block stay false on every
 * path. This note does not start a signer or sign a block.
 */
struct SwarmNotNoSignerResult {
    std::string code;
    bool started{false};
    bool signed_block{false};
};

/**
 * Note a node without starting a signer or signing a block. Order, first
 * match wins: an empty node_id is NODE. want_start is HELD. Otherwise the
 * note is NOTED and err is clear. started and signed_block stay false on
 * every path. This note does not start a signer or sign a block.
 */
SwarmNotNoSignerResult SwarmNoteNotNoSigner(const SwarmNotNoSigner& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIGNER_H

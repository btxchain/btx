// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FUNDSCRIPT_H
#define BTX_MODELNET_SWARM_FUNDSCRIPT_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory funding and refund leaves from the existing P2MR builders.
 * No broadcast, no network txid, and no spend-key signature.
 */
struct SwarmFundScript {
    std::vector<unsigned char> funding_script;
    std::vector<unsigned char> refund_script;
    bool bound{false};
};

/**
 * Assemble a 2-of-2 ML-DSA funding leaf and the sponsor refund leaf.
 * An empty builder result is FUNDING_SCRIPT. A refund leaf that does not
 * parse back to this sponsor and height is REFUND_UNBOUND. Either refusal
 * leaves the template unbound and both scripts empty.
 */
bool SwarmAssembleFundScript(const std::vector<unsigned char>& sponsor,
                             const std::vector<unsigned char>& worker,
                             int64_t refund_height,
                             SwarmFundScript& out,
                             std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FUNDSCRIPT_H

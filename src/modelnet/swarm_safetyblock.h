// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SAFETYBLOCK_H
#define BTX_MODELNET_SWARM_SAFETYBLOCK_H

#include <string>

namespace modelnet {

/**
 * A local note about one candidate. A safety failure or a broad
 * regression blocks graduation. Graduation is not provided.
 */
struct SwarmSafetyBlock {
    std::string candidate_id;
    bool safety_fail{false};
    bool broad_regression{false};
    bool want_graduate{false};
};

/**
 * A local safety note. graduated stays false: a note does not graduate
 * a candidate.
 */
struct SwarmSafetyBlockResult {
    std::string code;
    bool graduated{false};
};

/**
 * Order, first match wins: an empty candidate_id is SAFETY. A safety
 * failure or a broad regression is BLOCK, including when want_graduate
 * is also true. A request that wants graduation is HELD and err is
 * clear. Otherwise the note is NOTED and err is clear. graduated stays
 * false on every path. This records a local note. It does not graduate
 * a candidate.
 */
SwarmSafetyBlockResult SwarmNoteSafetyBlock(const SwarmSafetyBlock& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SAFETYBLOCK_H

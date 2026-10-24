// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_PASS_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_PASS_H

#include <string>

namespace modelnet {

/**
 * Refuse a request to pass a flagship stage.
 * A name outside the thirteen stages is STAGE.
 * Every listed stage is NOT_PASSED, whether or not evidence is recorded.
 * This call does not read or write evidence, and it has no pass bit to set.
 */
class SwarmFlagshipPass {
public:
    bool apply(const std::string& stage, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_PASS_H

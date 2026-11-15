// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SCRIPTROUTE_H
#define BTX_MODELNET_SWARM_SCRIPTROUTE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmScriptHop {
    std::vector<unsigned char> hash;
    std::vector<unsigned char> claimant;
    int expiry{0};
};

/**
 * Builds one SHA-256 claim leaf per hop and parses it back. Expiries must
 * rise by at least 160 blocks. qualified stays false: a built leaf is not a
 * settled multi-hop network. secp_penalty stays false. Nothing is broadcast.
 */
struct SwarmScriptRoute {
    bool scripts_ok{false};
    bool qualified{false};
    bool secp_penalty{false};
    std::string code;
    std::vector<std::vector<unsigned char>> scripts;
};

SwarmScriptRoute SwarmBuildScriptRoute(const std::vector<SwarmScriptHop>& hops, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SCRIPTROUTE_H

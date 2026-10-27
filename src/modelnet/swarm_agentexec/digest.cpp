// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/digest.h>

#include <hash.h>
#include <util/strencodings.h>

#include <string>

namespace modelnet {

std::string SwarmAgentExecDigest(const std::string& payload)
{
    return HexStr(Hash(payload));
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/quant.h>

#include <modelnet/swarm_kvmove/codes.h>

#include <string>
#include <vector>

namespace modelnet {

SwarmKvMoveQuant SwarmKvMoveClassifyQuant(const std::string& quantization, const std::vector<unsigned char>& body)
{
    if (quantization == kSwarmKvMoveQuant4bit) {
        return SwarmKvMoveQuant::Family;
    }
    if (quantization == kSwarmKvMoveQuantFull && !body.empty()) {
        return SwarmKvMoveQuant::Kv;
    }
    return SwarmKvMoveQuant::Reject;
}

} // namespace modelnet

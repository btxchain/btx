// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/quantization.h>

#include <modelnet/swarm_kvplace/codes.h>

#include <string>

namespace modelnet {

SwarmKvPlaceQuant SwarmKvPlaceClassify(const std::string& quantization, const std::string& checkpoint,
                                       const std::string& recipe)
{
    if (quantization == SWARM_KVPLACE_QUANT_4BIT) {
        return SwarmKvPlaceQuant::Family;
    }
    if (quantization == SWARM_KVPLACE_QUANT_FULL && !checkpoint.empty() && !recipe.empty()) {
        return SwarmKvPlaceQuant::Cohort;
    }
    return SwarmKvPlaceQuant::Reject;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/publish.h>

#include <modelnet/swarm_infer/codes.h>

#include <string>

namespace modelnet {

std::string SwarmInferHoldPublish(SwarmInferRateHold& hold, std::string& err)
{
    hold.published = false;
    hold.rate_stored = false;
    hold.tokens_per_sec = -1.0;
    err = SwarmInferCode::held;
    return SwarmInferCode::held;
}

} // namespace modelnet

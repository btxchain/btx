// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INFER_PUBLISH_H
#define BTX_MODELNET_SWARM_INFER_PUBLISH_H

#include <string>

namespace modelnet {

/**
 * A publish attempt. published stays false. rate_stored stays false.
 * tokens_per_sec stays -1. A held publish does not store a rate.
 */
struct SwarmInferRateHold {
    bool published{false};
    bool rate_stored{false};
    double tokens_per_sec{-1.0};
};

/**
 * Hold publication. Returns HELD. Clears any rate the caller may have
 * placed on the hold. Does not invent a tok/s.
 */
std::string SwarmInferHoldPublish(SwarmInferRateHold& hold, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INFER_PUBLISH_H

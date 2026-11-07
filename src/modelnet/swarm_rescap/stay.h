// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_STAY_H
#define BITCOIN_MODELNET_SWARM_RESCAP_STAY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * The stored thread count stays unraised and the cap stays 64.
 * refusal() is CAPPED. raised() stays false. cap_threads() stays 64.
 * This type does not store a count and does not move bytes.
 */
class SwarmResCapStay {
public:
    std::string refusal() const;
    bool raised() const;
    int64_t cap_threads() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_STAY_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_HOLD_H
#define BITCOIN_MODELNET_SWARM_NATPUB_HOLD_H

#include <string>

namespace modelnet {

/**
 * A stored claim is held, not published.
 * code() is HELD. published() stays false. There is no setter.
 */
class SwarmNatPubHold {
public:
    std::string code() const;
    bool published() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_HOLD_H

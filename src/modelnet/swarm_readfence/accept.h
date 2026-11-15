// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_ACCEPT_H
#define BITCOIN_MODELNET_SWARM_READFENCE_ACCEPT_H

#include <modelnet/swarm_readfence/span.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Stores one size.
 * A size is stored only when it is greater than 0 and at most 33554432.
 * Any other size is TRUNCATED and the span is unchanged.
 */
class SwarmReadAccept {
public:
    bool Apply(SwarmReadSpan& span, int64_t size, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_ACCEPT_H

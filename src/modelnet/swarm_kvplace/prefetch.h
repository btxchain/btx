// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_PREFETCH_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_PREFETCH_H

#include <modelnet/swarm_kvplace/offer.h>

#include <string>

namespace modelnet {

/**
 * Prefetch never starts an engine and never moves bytes.
 * An unknown fingerprint, or one that is not in KV, is NOT_COMPAT.
 * A fingerprint that was never offered is not reported as PREFIX_MISMATCH
 * and is not reported as ENGINE_ABSENT.
 * A fingerprint that is in KV returns false with ENGINE_ABSENT.
 */
bool SwarmKvPlacePrefetch(const SwarmKvPlaceBook& book, const std::string& fingerprint, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_PREFETCH_H

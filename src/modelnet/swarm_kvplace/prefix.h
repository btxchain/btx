// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_PREFIX_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_PREFIX_H

#include <modelnet/swarm_kvplace/offer.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Store a prefix on an offered fingerprint.
 * Length below 1 is PREFIX and stores nothing.
 * A fingerprint that is not a stored offer is PREFIX_MISMATCH.
 * That mismatch is never ENGINE_ABSENT.
 * A non-empty parent with parent_known false is CAUSAL_GAP and stores nothing.
 * An empty parent is stored even when parent_known is false.
 */
bool SwarmKvPlaceApplyPrefix(SwarmKvPlaceBook& book, const std::string& fingerprint, std::int64_t length,
                             const std::string& parent, bool parent_known, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_PREFIX_H

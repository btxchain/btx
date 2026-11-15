// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_SIGHASH_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_SIGHASH_H

#include <modelnet/swarm_routebook/types.h>

#include <string>

namespace modelnet {

/**
 * Record a sighash description.
 * covers_outputs false is NOT_SIGNED and does not store a covering description.
 * A false description leaves an earlier covering description in place.
 * covers_outputs true stores outputs_covered and clears err.
 * No key is attached. signed_ok stays false on the book that owns the path.
 */
bool SwarmRouteBookApplySighash(SwarmRouteBookPath& path, bool covers_outputs, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_SIGHASH_H

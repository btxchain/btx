// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_DIGEST_H
#define BITCOIN_MODELNET_SWARM_DEDUP_DIGEST_H

#include <modelnet/swarm_dedup/binding.h>

#include <string>

namespace modelnet {

/**
 * Bind digest_hex to a piece id when the two strings are equal.
 * A mismatch is CONFLICT and stores nothing. A second equal binding
 * is REPLAY and keeps the first. The piece body is not stored.
 */
bool SwarmPieceDedupDigest(SwarmPieceDedupBindings& bindings, const std::string& piece_id, const std::string& digest_hex, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_DIGEST_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_DIGEST_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_DIGEST_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Lowercase hex of the SHA-384 digest of [data, data + size).
 * A null data pointer or a zero size hashes the empty input.
 * The result is 96 hex characters. This does not store the bytes.
 */
std::string SwarmPiecePipeDigest(const unsigned char* data, std::size_t size);

/** Lowercase hex of the SHA-384 digest of body. An empty body hashes as empty. */
std::string SwarmPiecePipeDigest(const std::vector<unsigned char>& body);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_DIGEST_H

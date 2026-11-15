// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHLOCK_DIGEST_H
#define BITCOIN_MODELNET_SWARM_HASHLOCK_DIGEST_H

#include <uint256.h>

#include <vector>

namespace modelnet {

/**
 * One SHA-256 of bytes, in the byte order CSHA256 writes.
 * Hash() in hash.h is two rounds (CHash256). A hashlock uses one round,
 * the same primitive SHA256Uint256 and HashWriter::GetSHA256() implement.
 */
uint256 SwarmHashlockSha256(const std::vector<unsigned char>& bytes);

/**
 * True when both sides are 32 bytes and SHA-256(preimage) equals payment_hash.
 * A short preimage is not a match.
 */
bool SwarmHashlockDigestEquals(const std::vector<unsigned char>& payment_hash,
                               const std::vector<unsigned char>& preimage);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHLOCK_DIGEST_H

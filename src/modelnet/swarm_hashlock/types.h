// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHLOCK_TYPES_H
#define BITCOIN_MODELNET_SWARM_HASHLOCK_TYPES_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/** SHA-256 digest length. Any other preimage or payment-hash size claims nothing. */
inline constexpr std::size_t kSwarmHashlockDigestSize = 32;

/** Empty offer id, or a claim id that was never stored. */
inline constexpr char SWARM_HASHLOCK_INVOICE[] = "INVOICE";

/** payment_hash or preimage size is not 32. Nothing is stored. */
inline constexpr char SWARM_HASHLOCK_PREIMAGE[] = "PREIMAGE";

/** Duplicate offer id, or a second matching claim. The first result stays. */
inline constexpr char SWARM_HASHLOCK_REPLAY[] = "REPLAY";

/** SHA-256(preimage) is not the stored payment hash. Nothing is marked claimed. */
inline constexpr char SWARM_HASHLOCK_HASHLOCK[] = "HASHLOCK";

/**
 * One stored offer. payment_hash is the raw 32-byte single SHA-256 digest.
 * A failed offer is not inserted. claimed becomes true once.
 */
struct SwarmHashlockOffer {
    std::string id;
    std::vector<unsigned char> payment_hash;
    bool claimed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHLOCK_TYPES_H

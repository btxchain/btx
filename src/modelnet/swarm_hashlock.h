// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HASHLOCK_H
#define BTX_MODELNET_SWARM_HASHLOCK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one hashlock. invoice_id names the invoice.
 * hash_len is the claimed SHA-256 hash length in bytes. preimage_len is
 * the claimed preimage length in bytes. want_qualify asks this note to
 * treat the hashlock as a qualified route.
 *
 * A routed payment uses a 32-byte preimage and a 32-byte SHA-256 hashlock.
 * This note does not qualify a route. qualified stays false on every path.
 * Nothing is routed and nothing is broadcast. No hostnames or IPs are used.
 */
struct SwarmHashlockRequest {
    std::string invoice_id;
    int64_t hash_len{0};
    int64_t preimage_len{0};
    bool want_qualify{false};
};

/**
 * Outcome of noting a hashlock. qualified stays false: nothing is routed
 * and nothing is broadcast.
 */
struct SwarmHashlockResult {
    bool qualified{false};
    std::string code;
};

/**
 * Note a hashlock without qualifying a route.
 * Order, first match wins:
 * an empty invoice_id, hash_len < 0, or preimage_len < 0 is HASH.
 * hash_len other than 32 is HASH_LEN, including when want_qualify is true.
 * preimage_len other than 32 is PREIMAGE, including when want_qualify is true.
 * A routed payment uses a 32-byte preimage and a 32-byte SHA-256 hashlock.
 * want_qualify is HELD and err is cleared. This note does not qualify a route.
 * Otherwise the note is NOTED and err is cleared.
 * qualified stays false. Nothing is routed and nothing is broadcast.
 */
SwarmHashlockResult SwarmNoteHashlock(const SwarmHashlockRequest& hashlock, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HASHLOCK_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVMOVE_H
#define BITCOIN_MODELNET_SWARM_KVMOVE_H

#include <modelnet/swarm_kvmove/slot.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process KV page move.
 *
 * This plane copies a resident page from one slot to another when the engine
 * is the in-process memory engine. It does not open a socket. Remote engines
 * do not move bytes. launched() stays false. gpu() stays false. There is no
 * method that sets either true.
 *
 * Put stores a slot. An empty slot or an empty fingerprint is PAGE and stores
 * nothing. "4bit" stores the slot as family-only: in_family true, in_kv false,
 * and the body is not kept. "full" with a non-empty body stores a copy of the
 * body, sets in_family and in_kv true. Any other quantization, including
 * "full" with an empty body, is QUANTIZATION and stores nothing. A second put
 * of the same slot is REPLAY and keeps the first body. Empty slot or empty
 * fingerprint is decided before replay and before quantization.
 *
 * Move copies bytes only for engine "memory" when both slots are already in
 * KV and their fingerprints are equal. The dst body becomes a byte copy of
 * the src body, and that size is added to bytes_moved(). Unknown src or dst
 * is PAGE. "nixl", "mooncake", and "rdma" are ENGINE_ABSENT and copy nothing.
 * Any other engine name is ENGINE. A memory move whose src is not in KV, whose
 * dst is not in KV, or whose fingerprints differ is NOT_COMPAT and copies
 * nothing. A 4bit dst has a different quantization from a full src, so it
 * stays out of KV unless a copy succeeds under the equal-fingerprint rule.
 *
 * Refusal paths return false and set err to the code. Accepted paths return
 * true and clear err.
 */
class SwarmKvMove {
public:
    bool Put(const std::string& slot, const std::string& fingerprint, const std::string& quantization,
             const std::vector<unsigned char>& body, std::string& err);
    bool Move(const std::string& src, const std::string& dst, const std::string& engine, std::string& err);

    bool in_family(const std::string& slot) const;
    bool in_kv(const std::string& slot) const;
    std::size_t body_size(const std::string& slot) const;
    const std::vector<unsigned char>& body(const std::string& slot) const;
    std::int64_t bytes_moved() const;
    bool launched() const;
    bool gpu() const;

private:
    SwarmKvMoveBook m_book;
    std::int64_t m_bytes_moved{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVMOVE_H

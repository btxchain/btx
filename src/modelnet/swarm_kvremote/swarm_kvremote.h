// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVREMOTE_H
#define BITCOIN_MODELNET_SWARM_KVREMOTE_H

#include <modelnet/swarm_kvmove/swarm_kvmove.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Remote KV transfer.
 *
 * Put and Move forward to SwarmKvMove. The memory engine copies bytes
 * only inside that call. This type does not copy a page itself. Remote
 * engines do not move bytes. There is no socket.
 *
 * Put stores a slot through SwarmKvMove::Put. Quantization "full" with a
 * non-empty body is resident: in_family and in_kv are true and the body
 * is kept. "4bit" is family-only: in_family is true, in_kv is false, and
 * the body is not a KV body. Refusal codes are the mover's codes.
 *
 * Move calls SwarmKvMove::Move. engine "memory" copies when that call
 * succeeds. On success, bytes_moved() equals SwarmKvMove::bytes_moved()
 * and the dst body equals the src body. engines "nixl", "mooncake", and
 * "rdma" call Move as well and return false with ENGINE_ABSENT. Those
 * calls do not increase bytes_moved(). Different fingerprints are
 * NOT_COMPAT and copy nothing.
 *
 * Transfer puts src and dst under one fingerprint, quantization "full".
 * The src body is the caller's body. The dst body is one different byte.
 * It then moves with engine "memory". The result is true only when that
 * move returns true. page_bytes() is bytes_moved().
 *
 * Remote calls Move with engine "nixl". After a successful Transfer that
 * returns false with ENGINE_ABSENT and adds no bytes.
 *
 * launched() and gpu() stay false. There is no method that sets either
 * true. broadcast() stays false. automatic_spend() returns "0".
 */
class SwarmKvRemote {
public:
    bool Put(const std::string& slot, const std::string& fingerprint, const std::string& quantization,
             const std::vector<unsigned char>& body, std::string& err);
    bool Move(const std::string& src, const std::string& dst, const std::string& engine, std::string& err);
    bool Transfer(const std::string& src, const std::string& dst, const std::vector<unsigned char>& body,
                  std::string& err);
    bool Remote(const std::string& src, const std::string& dst, std::string& err);

    bool in_family(const std::string& slot) const;
    bool in_kv(const std::string& slot) const;
    std::size_t body_size(const std::string& slot) const;
    const std::vector<unsigned char>& body(const std::string& slot) const;
    std::int64_t bytes_moved() const;
    std::int64_t page_bytes() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;

private:
    SwarmKvMove m_move;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVREMOTE_H

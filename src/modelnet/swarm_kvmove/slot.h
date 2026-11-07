// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVMOVE_SLOT_H
#define BITCOIN_MODELNET_SWARM_KVMOVE_SLOT_H

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One stored slot.
 * in_family is true for every stored slot.
 * in_kv is true only for "full" with a non-empty body, and that body is kept.
 * A "4bit" slot keeps the fingerprint and drops the body.
 */
struct SwarmKvMoveSlot {
    std::string fingerprint;
    std::string quantization;
    bool in_family{false};
    bool in_kv{false};
    std::vector<unsigned char> body;
};

/**
 * Slots keyed by slot id.
 * An empty slot or an empty fingerprint is PAGE and stores nothing.
 * A slot already stored is REPLAY and the first body stays, including when
 * the new quantization would have been refused or would have replaced the body.
 * "4bit" stores family-only. "full" with a non-empty body stores those bytes
 * and marks the slot in KV. Any other quantization stores nothing.
 */
class SwarmKvMoveBook {
public:
    bool Put(const std::string& slot, const std::string& fingerprint, const std::string& quantization,
             const std::vector<unsigned char>& body, std::string& err);

    bool in_family(const std::string& slot) const;
    bool in_kv(const std::string& slot) const;
    std::size_t body_size(const std::string& slot) const;
    const std::vector<unsigned char>& body(const std::string& slot) const;

    const SwarmKvMoveSlot* Find(const std::string& slot) const;
    SwarmKvMoveSlot* Find(const std::string& slot);

private:
    std::map<std::string, SwarmKvMoveSlot> m_slots;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVMOVE_SLOT_H

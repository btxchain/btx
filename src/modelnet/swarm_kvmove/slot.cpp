// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/slot.h>

#include <modelnet/swarm_kvmove/bytes.h>
#include <modelnet/swarm_kvmove/codes.h>
#include <modelnet/swarm_kvmove/quant.h>

#include <cstddef>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmKvMoveBook::Put(const std::string& slot, const std::string& fingerprint, const std::string& quantization,
                          const std::vector<unsigned char>& body, std::string& err)
{
    if (slot.empty() || fingerprint.empty()) {
        err = kSwarmKvMovePage;
        return false;
    }
    if (Find(slot) != nullptr) {
        err = kSwarmKvMoveReplay;
        return false;
    }
    const SwarmKvMoveQuant kind = SwarmKvMoveClassifyQuant(quantization, body);
    if (kind == SwarmKvMoveQuant::Reject) {
        err = kSwarmKvMoveQuantization;
        return false;
    }

    SwarmKvMoveSlot row;
    row.fingerprint = fingerprint;
    row.quantization = quantization;
    row.in_family = true;
    row.in_kv = kind == SwarmKvMoveQuant::Kv;
    if (row.in_kv) {
        row.body = SwarmKvMoveCopyBytes(body);
    }
    m_slots.emplace(slot, std::move(row));
    err.clear();
    return true;
}

bool SwarmKvMoveBook::in_family(const std::string& slot) const
{
    const SwarmKvMoveSlot* row = Find(slot);
    return row != nullptr && row->in_family;
}

bool SwarmKvMoveBook::in_kv(const std::string& slot) const
{
    const SwarmKvMoveSlot* row = Find(slot);
    return row != nullptr && row->in_kv;
}

std::size_t SwarmKvMoveBook::body_size(const std::string& slot) const
{
    const SwarmKvMoveSlot* row = Find(slot);
    if (row == nullptr) {
        return 0;
    }
    return row->body.size();
}

const std::vector<unsigned char>& SwarmKvMoveBook::body(const std::string& slot) const
{
    static const std::vector<unsigned char> kEmpty;
    const SwarmKvMoveSlot* row = Find(slot);
    if (row == nullptr) {
        return kEmpty;
    }
    return row->body;
}

const SwarmKvMoveSlot* SwarmKvMoveBook::Find(const std::string& slot) const
{
    const auto found = m_slots.find(slot);
    if (found == m_slots.end()) {
        return nullptr;
    }
    return &found->second;
}

SwarmKvMoveSlot* SwarmKvMoveBook::Find(const std::string& slot)
{
    const auto found = m_slots.find(slot);
    if (found == m_slots.end()) {
        return nullptr;
    }
    return &found->second;
}

} // namespace modelnet
